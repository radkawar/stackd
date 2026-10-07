#!/usr/bin/env python3
"""Local two-binary Lambda encrypted-filter proof; never calls native AWS.

Run before against the old binary, retain state, then run after against the new
binary. Requires Docker, the installed Python 3.12 Lambda image and telemetry.
Every SDK call has retries disabled; failed runs retain their evidence.
"""
import argparse
import base64
import hashlib
import io
import json
import os
from pathlib import Path
import socket
import sqlite3
import subprocess
import time
import traceback
import uuid
import zipfile

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

from msk_executable_smoke import require
from stackd_process import StackdProcess

FILTERS = {'Filters': [{'Pattern': '{"body":{"kind":["keep"]}}'}]}
HANDLER = '''import json, os
import boto3

def invoke(event, context):
    receipt = {'request_id': context.aws_request_id, 'runtime_api': bool(os.environ.get('AWS_LAMBDA_RUNTIME_API')), 'event': event}
    boto3.client('sqs', endpoint_url=os.environ['PROOF_ENDPOINT']).send_message(QueueUrl=os.environ['QUEUE_URL'], MessageBody=json.dumps(receipt))
    return {'processed': len(event['Records'])}
'''


class Proof:
    def __init__(self, args):
        self.args = args
        self.state = Path(args.state_directory).resolve()
        self.state.mkdir(parents=True, exist_ok=True)
        self.manifest = self.state / 'owned.json'
        if args.phase in ('before', 'runtime'):
            require(not self.manifest.exists(), 'fresh before/runtime state required')
            with socket.socket() as sock:
                sock.bind(('127.0.0.1', 0))
                port = sock.getsockname()[1]
            self.owned = {'prefix': 'filter-sign-' + uuid.uuid4().hex[:10], 'port': port, 'mappings': [], 'queues': [], 'keys': []}
        else:
            self.owned = json.loads(self.manifest.read_text())
        self.endpoint = f"http://127.0.0.1:{self.owned['port']}"
        self.directory = self.state / args.phase
        self.directory.mkdir(exist_ok=True)
        self.controller = StackdProcess(self.directory)
        self.env = {k: v for k, v in os.environ.items() if not k.startswith('AWS_')}
        self.env['AWS_EC2_METADATA_DISABLED'] = 'true'
        self.report = {'phase': args.phase, 'binary_sha256': hashlib.file_digest(open(args.binary, 'rb'), 'sha256').hexdigest(),
            'scope': 'Local signed boto3 requests, retained SQLite and real Docker Lambda Runtime API. No native AWS calls or claim of native Lambda ciphertext compatibility.',
            'sources': ['testdata/aws/lambda/filter_kms_native.json', 'https://docs.aws.amazon.com/lambda/latest/dg/security-encryption-at-rest.html'],
            'observations': {}, 'controllers': self.controller.runs, 'cleanup': {}, 'failures': []}
        self.clients = {name: boto3.client(name, endpoint_url=self.endpoint, region_name='us-east-1', aws_access_key_id='test',
            aws_secret_access_key='test', config=Config(retries={'total_max_attempts': 1}, connect_timeout=5, read_timeout=90))
            for name in ('lambda', 'sqs', 'iam', 'kms', 'logs')}
        self.fn, self.sqs, self.iam, self.kms = [self.clients[name] for name in ('lambda', 'sqs', 'iam', 'kms')]

    def save(self):
        self.manifest.write_text(json.dumps(self.owned, indent=2) + '\n')
        Path(self.args.output).write_text(json.dumps(self.report, default=str, indent=2) + '\n')

    def record(self, label, value):
        self.report['observations'][label] = value
        self.save()
        return value

    def start(self):
        self.controller.start([str(Path(self.args.binary).resolve()), '-listen', f"0.0.0.0:{self.owned['port']}",
            '-public-endpoint', self.endpoint, '-database', str(self.state / 'state.sqlite'),
            '-docker-host', self.args.docker_host, '-lambda-runtime', '-lambda-telemetry-directory', str(Path(self.args.telemetry_directory).resolve()),
            '-compute-endpoint', self.endpoint.replace('127.0.0.1', 'host.docker.internal')], self.endpoint, environment=self.env, timeout=180)

    def wait(self, predicate, label, timeout=120):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            value = predicate()
            if value:
                return value
            time.sleep(.2)
        raise TimeoutError(label)

    def error(self, label, operation, **params):
        try:
            value = operation(**params)
        except ClientError as error:
            return self.record(label, error.response['Error'])
        self.record(label, {'unexpected_success': value})
        raise AssertionError(label + ' unexpectedly succeeded')

    def absent(self, operation, code, **params):
        try:
            operation(**params)
        except ClientError as error:
            require(error.response['Error']['Code'] == code, str(error))
            return True
        return False

    def policy(self, required=False, deny=False):
        statements = [{'Effect': 'Allow', 'Principal': {'AWS': 'arn:aws:iam::000000000000:root'}, 'Action': 'kms:*', 'Resource': '*'},
            {'Effect': 'Allow', 'Principal': {'Service': 'lambda.us-east-1.amazonaws.com'}, 'Action': 'kms:Decrypt', 'Resource': '*',
             'Condition': {'StringEquals': {'kms:EncryptionContext:aws:lambda:FunctionArn': self.owned['function_arn'],
                 'kms:EncryptionContext:aws:lambda:EventSourceArn': self.owned['source_arn']}}}]
        if required:
            statements.append({'Effect': 'Deny', 'Principal': '*', 'Action': ['kms:GenerateDataKey', 'kms:Decrypt'], 'Resource': '*',
                'Condition': {'Null': {'kms:EncryptionContext:aws-crypto-public-key': 'true'}}})
        if deny:
            statements.append({'Effect': 'Deny', 'Principal': '*', 'Action': 'kms:Decrypt', 'Resource': '*'})
        return json.dumps({'Version': '2012-10-17', 'Statement': statements})

    def set_policy(self, key, **options):
        policy = self.policy(**options)
        self.kms.put_key_policy(KeyId=key, PolicyName='default', Policy=policy)
        self.record('policy_' + str(len(self.report['observations'])), json.loads(policy))

    def mapping(self):
        return self.fn.get_event_source_mapping(UUID=self.owned['mapping'])

    def settled(self, enabled=False):
        state = 'Enabled' if enabled else 'Disabled'
        return self.wait(lambda: self.mapping()['State'] == state, 'mapping ' + state)

    def storage(self):
        with sqlite3.connect(self.state / 'state.sqlite') as db:
            db.row_factory = sqlite3.Row
            row = dict(db.execute('SELECT * FROM lambda_event_source_filter_encryption WHERE uuid=?', (self.owned['mapping'],)).fetchone())
        return {name: base64.b64encode(value).decode() if isinstance(value, bytes) else value for name, value in row.items()}

    def provision(self):
        prefix = self.owned['prefix']
        for suffix in ('source', 'out'):
            queue = self.sqs.create_queue(QueueName=prefix + '-' + suffix)['QueueUrl']
            self.owned['queues'].append(queue)
            self.owned[suffix] = queue
            self.owned[suffix + '_arn'] = self.sqs.get_queue_attributes(QueueUrl=queue, AttributeNames=['QueueArn'])['Attributes']['QueueArn']
            self.save()
        role = self.iam.create_role(RoleName=prefix, AssumeRolePolicyDocument=json.dumps({'Version': '2012-10-17', 'Statement': [
            {'Effect': 'Allow', 'Principal': {'Service': 'lambda.amazonaws.com'}, 'Action': 'sts:AssumeRole'}]}))['Role']['Arn']
        self.owned['role'] = prefix
        self.iam.put_role_policy(RoleName=prefix, PolicyName='source-output', PolicyDocument=json.dumps({'Version': '2012-10-17', 'Statement': [
            {'Effect': 'Allow', 'Action': ['sqs:ReceiveMessage', 'sqs:DeleteMessage', 'sqs:GetQueueAttributes'], 'Resource': self.owned['source_arn']},
            {'Effect': 'Allow', 'Action': 'sqs:SendMessage', 'Resource': self.owned['out_arn']},
            {'Effect': 'Allow', 'Action': ['logs:CreateLogGroup', 'logs:CreateLogStream', 'logs:PutLogEvents'], 'Resource': '*'},
            {'Effect': 'Deny', 'Action': ['kms:Decrypt', 'kms:GenerateDataKey'], 'Resource': '*'}]}))
        package = io.BytesIO()
        with zipfile.ZipFile(package, 'w') as archive:
            archive.writestr('entry.py', HANDLER)
        self.owned['function_arn'] = self.fn.create_function(FunctionName=prefix, Runtime='python3.12', Handler='entry.invoke', Role=role,
            Code={'ZipFile': package.getvalue()}, Timeout=20, MemorySize=128, Environment={'Variables': {
                'PROOF_ENDPOINT': self.endpoint.replace('127.0.0.1', 'host.docker.internal'),
                'QUEUE_URL': self.owned['out'].replace('127.0.0.1', 'host.docker.internal')}})['FunctionArn']
        self.save()
        self.wait(lambda: self.fn.get_function_configuration(FunctionName=prefix)['State'] == 'Active', 'function readiness')
        key = self.kms.create_key(Policy=self.policy(required=True))['KeyMetadata']['Arn']
        self.owned['keys'].append(key)
        self.owned['key'] = key
        self.save()
        return {'FunctionName': prefix, 'EventSourceArn': self.owned['source_arn'], 'Enabled': False,
            'BatchSize': 1, 'FilterCriteria': FILTERS, 'KMSKeyArn': key}

    def before(self):
        params = self.provision()
        key = self.owned['key']
        failure = self.error('create_required_public_key', self.fn.create_event_source_mapping, **params)
        require('kms:GenerateDataKey' in failure.get('Message', '') and 'denies' in failure['Message'], 'create did not fail due to signing context')
        self.set_policy(key)
        mapping = self.fn.create_event_source_mapping(**params)
        self.owned['mapping'] = mapping['UUID']
        self.owned['mappings'].append(mapping['UUID'])
        self.save()
        self.settled()
        self.set_policy(key, required=True)
        failure = self.error('update_required_public_key', self.fn.update_event_source_mapping, UUID=mapping['UUID'], FilterCriteria=FILTERS)
        require('kms:GenerateDataKey' in failure.get('Message', '') and 'denies' in failure['Message'], 'update did not fail due to signing context')
        self.set_policy(key)
        require(self.mapping()['FilterCriteria'] == FILTERS, 'legacy read mismatch')
        self.record('legacy_mapping', self.mapping())
        self.record('legacy_storage', self.storage())
        self.owned['legacy_ciphertext_sha256'] = hashlib.sha256(base64.b64decode(self.storage()['content'])).hexdigest()
        self.report['status'] = 'before-captured; resources retained for after phase'

    def runtime(self):
        mapping = self.fn.create_event_source_mapping(**self.provision())
        self.owned['mapping'] = mapping['UUID']
        self.owned['mappings'].append(mapping['UUID'])
        self.save()
        self.settled()
        self.record('initial_signed_mapping', mapping)
        self.after()

    def receive(self):
        rows = self.sqs.receive_message(QueueUrl=self.owned['out'], MaxNumberOfMessages=10, WaitTimeSeconds=1).get('Messages', [])
        for row in rows:
            self.sqs.delete_message(QueueUrl=self.owned['out'], ReceiptHandle=row['ReceiptHandle'])
        return [json.loads(row['Body']) for row in rows]

    def send(self, label, kind='keep'):
        return self.sqs.send_message(QueueUrl=self.owned['source'], MessageBody=json.dumps({'kind': kind, 'id': label}))['MessageId']

    def delivery(self, label):
        receipt = self.wait(self.receive, label + ' real Runtime API receipt', 180)
        self.record(label, receipt)
        require(len(receipt) == 1 and receipt[0]['runtime_api'], 'not one actual Lambda receipt')
        records = receipt[0]['event']['Records']
        require(len(records) == 1 and json.loads(records[0]['body']) == {'kind': 'keep', 'id': label}, 'unexpected accepted event')
        require(records[0]['eventSourceARN'] == self.owned['source_arn'], 'source mismatch')
        require(not self.receive(), 'extra invocation accepted a dropped or duplicate event')
        attributes = ['ApproximateNumberOfMessages', 'ApproximateNumberOfMessagesNotVisible', 'ApproximateNumberOfMessagesDelayed']
        def drained():
            counts = self.sqs.get_queue_attributes(QueueUrl=self.owned['source'], AttributeNames=attributes)['Attributes']
            return counts if all(int(counts[name]) == 0 for name in attributes) else None
        self.record(label + '_source_drained', self.wait(drained, label + ' source acknowledgement'))

    def after(self):
        if self.args.phase == 'after':
            old = self.storage()
            require(hashlib.sha256(base64.b64decode(old['content'])).hexdigest() == self.owned['legacy_ciphertext_sha256'],
                'retained legacy ciphertext changed across binary migration')
            require(not old.get('format'), 'retained legacy row was relabeled as signed')
            require(self.mapping()['FilterCriteria'] == FILTERS, 'retained legacy mapping unreadable')
            require(self.storage() == old, 'legacy read opportunistically rewrote ciphertext')
            self.record('legacy_reopen_without_rewrite', self.mapping())
        key = self.kms.create_key(Policy=self.policy(required=True))['KeyMetadata']['Arn']
        self.owned['keys'].append(key)
        self.owned['signed_key'] = key
        self.save()
        updated = self.fn.update_event_source_mapping(UUID=self.owned['mapping'], KMSKeyArn=key, FilterCriteria=FILTERS)
        self.settled()
        self.record('signed_update_rekey', updated)
        require(self.mapping()['FilterCriteria'] == FILTERS, 'signed Get exact filters mismatch')
        fresh_queue = self.sqs.create_queue(QueueName=self.owned['prefix'] + '-fresh')['QueueUrl']
        self.owned['queues'].append(fresh_queue)
        self.save()
        fresh_arn = self.sqs.get_queue_attributes(QueueUrl=fresh_queue, AttributeNames=['QueueArn'])['Attributes']['QueueArn']
        self.iam.put_role_policy(RoleName=self.owned['role'], PolicyName='fresh-source', PolicyDocument=json.dumps({
            'Version': '2012-10-17', 'Statement': [{'Effect': 'Allow',
                'Action': ['sqs:ReceiveMessage', 'sqs:DeleteMessage', 'sqs:GetQueueAttributes'], 'Resource': fresh_arn}]}))
        self.owned['fresh_policy'] = True
        self.save()
        fresh = self.fn.create_event_source_mapping(FunctionName=self.owned['prefix'], EventSourceArn=fresh_arn,
            Enabled=False, BatchSize=1, KMSKeyArn=key, FilterCriteria=FILTERS)
        self.owned['mappings'].append(fresh['UUID'])
        self.save()
        require(fresh['FilterCriteria'] == FILTERS, 'fresh signed create changed filters')
        self.record('fresh_signed_create', fresh)
        listed = self.fn.list_event_source_mappings(FunctionName=self.owned['prefix'])['EventSourceMappings']
        require(len(listed) == 2 and all(not row.get('FilterCriteria') for row in listed), 'List leaked filters')
        self.record('list_redaction', listed)
        self.record('signed_storage', self.storage())
        self.interop()
        self.set_policy(key, required=True, deny=True)
        denied = self.record('current_deny_get', self.mapping())
        require(denied.get('FilterCriteriaError', {}).get('ErrorCode') == 'AccessDeniedException' and not denied.get('FilterCriteria'), 'current deny ignored')
        self.set_policy(key, required=True)
        require(self.mapping()['FilterCriteria'] == FILTERS, 'deny recovery failed')
        self.fn.update_event_source_mapping(UUID=self.owned['mapping'], Enabled=True)
        self.settled(True)
        self.send('initial-drop', 'drop')
        self.send('initial-keep')
        self.delivery('initial-keep')
        self.runtime_evidence()
        self.fn.update_event_source_mapping(UUID=self.owned['mapping'], Enabled=False)
        self.settled()
        self.kms.disable_key(KeyId=key)
        disabled = self.record('current_disabled_get', self.mapping())
        require(disabled.get('FilterCriteriaError', {}).get('ErrorCode') == 'DisabledException', 'disabled key ignored')
        # Join previously authorized long polls before exercising new admission.
        self.controller.stop()
        self.start()
        self.fn.update_event_source_mapping(UUID=self.owned['mapping'], Enabled=True)
        self.settled(True)
        self.send('disable-recovery')
        time.sleep(3)
        require(not self.record('disabled_key_receipts', self.receive()), 'disabled key allowed delivery')
        pending = self.record('disabled_source_retained', self.sqs.get_queue_attributes(QueueUrl=self.owned['source'],
            AttributeNames=['ApproximateNumberOfMessages', 'ApproximateNumberOfMessagesNotVisible'])['Attributes'])
        require(pending == {'ApproximateNumberOfMessages': '1', 'ApproximateNumberOfMessagesNotVisible': '0'}, 'disabled key consumed source message')
        self.kms.enable_key(KeyId=key)
        self.delivery('disable-recovery')
        self.fn.update_event_source_mapping(UUID=self.owned['mapping'], Enabled=False)
        self.settled()
        self.set_policy(key, required=True, deny=True)
        self.controller.stop()
        self.start()
        self.fn.update_event_source_mapping(UUID=self.owned['mapping'], Enabled=True)
        self.settled(True)
        self.send('deny-recovery')
        time.sleep(3)
        require(not self.record('denied_key_receipts', self.receive()), 'current key deny allowed poller delivery')
        pending = self.record('denied_source_retained', self.sqs.get_queue_attributes(QueueUrl=self.owned['source'],
            AttributeNames=['ApproximateNumberOfMessages', 'ApproximateNumberOfMessagesNotVisible'])['Attributes'])
        require(pending == {'ApproximateNumberOfMessages': '1', 'ApproximateNumberOfMessagesNotVisible': '0'}, 'denied key consumed source message')
        self.set_policy(key, required=True)
        self.delivery('deny-recovery')
        self.record('execution_role_kms_denied_service_principal_succeeded', True)
        self.controller.stop()
        self.start()
        require(self.mapping()['FilterCriteria'] == FILTERS, 'signed filters failed restart')
        self.send('restart-drop', 'drop')
        self.send('restart-keep')
        self.delivery('restart-keep')
        self.report['status'] = 'passed'

    def interop(self):
        if not self.args.esdk_python:
            self.record('official_reader', {'status': 'not_requested'})
            return
        source = '''import base64, hashlib, json, sys
sys.path.insert(0, sys.argv[1])
import aws_encryption_sdk
import boto3
from botocore.config import Config
from aws_encryption_sdk.key_providers.kms import KMSMasterKey
data = json.load(sys.stdin)
kms = boto3.client('kms', endpoint_url=data['endpoint'], region_name='us-east-1', aws_access_key_id='test', aws_secret_access_key='test', config=Config(retries={'total_max_attempts': 1}))
key = KMSMasterKey(key_id=data['key'], client=kms)
plain, header = aws_encryption_sdk.EncryptionSDKClient().decrypt(source=base64.b64decode(data['content']), key_provider=key)
size = int.from_bytes(plain[:2], 'big')
assert plain[2:2+size].decode() == data['mapping_arn'], 'private mapping binding differs'
assert json.loads(plain[2+size:]) == data['patterns'], 'filter plaintext differs'
assert set(header.encryption_context) == {'aws-crypto-public-key', 'aws:lambda:EventSourceArn', 'aws:lambda:FunctionArn'}
assert header.encryption_context['aws:lambda:EventSourceArn'] == data['source_arn']
assert header.encryption_context['aws:lambda:FunctionArn'] == data['function_arn']
print(json.dumps({'version': aws_encryption_sdk.__version__, 'algorithm': hex(header.algorithm.algorithm_id), 'context': header.encryption_context, 'private_mapping_binding': plain[2:2+size].decode(), 'plaintext_sha256': hashlib.sha256(plain).hexdigest(), 'exact_patterns': json.loads(plain[2+size:])}))
'''
        result = subprocess.run([self.args.esdk_python, '-c', source, self.args.esdk_directory], input=json.dumps({
            'endpoint': self.endpoint, 'key': self.owned['signed_key'], 'content': self.storage()['content'],
            'mapping_arn': self.mapping()['EventSourceMappingArn'], 'patterns': [row['Pattern'] for row in FILTERS['Filters']],
            'source_arn': self.owned['source_arn'], 'function_arn': self.owned['function_arn']}),
            text=True, capture_output=True, env=self.env, timeout=60)
        self.record('official_reader_process', {'exit': result.returncode, 'stdout': result.stdout, 'stderr': result.stderr})
        require(result.returncode == 0, 'official ESDK reader failed')
        self.record('official_reader', json.loads(result.stdout))

    def docker(self, *args):
        result = subprocess.run(['docker', '--host', self.args.docker_host, *args], text=True, capture_output=True, timeout=30)
        require(result.returncode == 0, result.stderr)
        return result.stdout.strip()

    def namespace(self):
        return 'stackd-lambda-' + hashlib.sha256(str(self.state / 'state.sqlite').encode()).hexdigest()[:24]

    def runtime_evidence(self):
        ids = self.docker('ps', '-aq', '--filter', 'label=io.stackd.lambda.instance=' + self.namespace()).split()
        require(ids, 'no owned Docker runtime exists after invocation')
        rows = json.loads(self.docker('inspect', *ids))
        runtime = [row for row in rows if 'AWS_EXECUTION_ENV=AWS_Lambda_python3.12' in row['Config'].get('Env', [])]
        require(runtime, 'owned containers contain no Python Lambda runtime')
        require(all(row['Config']['Labels'].get('io.stackd.function', '').split(':function:')[-1].split(':')[0] == self.owned['prefix'] for row in runtime), 'runtime function ownership mismatch')
        self.record('actual_docker_runtime', [{'id': row['Id'], 'image': row['Image'], 'labels': row['Config']['Labels'],
            'entrypoint': row['Config']['Entrypoint']} for row in runtime])

    def docker_clean(self):
        containers = self.docker('ps', '-aq', '--filter', 'label=io.stackd.lambda.instance=' + self.namespace()).split()
        volumes = self.docker('volume', 'ls', '-q', '--filter', 'label=io.stackd.lambda.instance=' + self.namespace()).split()
        self.report['cleanup']['docker'] = {'namespace': self.namespace(), 'containers': containers, 'volumes': volumes}
        require(not containers and not volumes, 'owned runtime resources survived controller stop')

    def cleanup(self):
        for mapping in self.owned['mappings']:
            self.fn.delete_event_source_mapping(UUID=mapping)
            self.wait(lambda: self.absent(self.fn.get_event_source_mapping, 'ResourceNotFoundException', UUID=mapping), 'mapping deletion')
        self.report['cleanup']['mappings_absent'] = True
        self.fn.delete_function(FunctionName=self.owned['prefix'])
        require(self.absent(self.fn.get_function, 'ResourceNotFoundException', FunctionName=self.owned['prefix']), 'function remains')
        self.report['cleanup']['function_absent'] = True
        for queue in self.owned['queues']:
            self.sqs.delete_queue(QueueUrl=queue)
            require(self.absent(self.sqs.get_queue_attributes, 'AWS.SimpleQueueService.NonExistentQueue', QueueUrl=queue, AttributeNames=['QueueArn']), 'queue remains')
        self.report['cleanup']['queues_absent'] = True
        self.iam.delete_role_policy(RoleName=self.owned['role'], PolicyName='source-output')
        if self.owned.get('fresh_policy'):
            self.iam.delete_role_policy(RoleName=self.owned['role'], PolicyName='fresh-source')
        self.iam.delete_role(RoleName=self.owned['role'])
        require(self.absent(self.iam.get_role, 'NoSuchEntity', RoleName=self.owned['role']), 'role remains')
        self.report['cleanup']['role_absent'] = True
        try:
            self.clients['logs'].delete_log_group(logGroupName='/aws/lambda/' + self.owned['prefix'])
        except ClientError as error:
            require(error.response['Error']['Code'] == 'ResourceNotFoundException', str(error))
        self.report['cleanup']['logs_deleted'] = True
        for key in self.owned['keys']:
            self.set_policy(key)
            self.kms.schedule_key_deletion(KeyId=key, PendingWindowInDays=7)
        self.report['cleanup']['local_keys'] = 'PendingDeletion (7-day KMS API minimum); no native key created'

    def run(self):
        try:
            self.start()
            getattr(self, self.args.phase)()
        except BaseException:
            self.report['failures'].append(traceback.format_exc())
            self.report['status'] = 'failed'
            raise
        finally:
            try:
                if self.args.phase != 'before' and self.controller.process is not None:
                    self.cleanup()
            except BaseException:
                self.report['failures'].append(traceback.format_exc())
                self.report['status'] = 'failed'
                raise
            finally:
                try:
                    self.controller.stop(timeout=90)
                    self.docker_clean()
                finally:
                    self.save()
        print(json.dumps({'status': self.report['status'], 'evidence': self.args.output, 'state': str(self.state)}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('phase', choices=('before', 'after', 'runtime'))
    parser.add_argument('--binary', default='bin/stackd')
    parser.add_argument('--state-directory', required=True)
    parser.add_argument('--output', required=True)
    parser.add_argument('--docker-host', default='unix:///var/run/docker.sock')
    parser.add_argument('--telemetry-directory', default='bin')
    parser.add_argument('--esdk-python')
    parser.add_argument('--esdk-directory', default='/tmp/stackd-esdk-reader')
    Proof(parser.parse_args()).run()


if __name__ == '__main__':
    main()
