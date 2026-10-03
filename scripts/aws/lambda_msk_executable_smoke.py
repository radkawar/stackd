#!/usr/bin/env python3
"""Signed MSK -> real OCI Lambda proof, broker offsets, retries and SQLite reopen."""
import argparse
import base64
import datetime
import io
import json
from pathlib import Path
import sqlite3
import time
import uuid
import zipfile

from botocore.exceptions import ClientError

from msk_executable_smoke import Proof, require

HANDLER = '''import base64, json, os
import boto3

def invoke(event, context):
    values = [r for rows in event['records'].values() for r in rows]
    fail = False
    for record in values:
        try:
            item = json.loads(base64.b64decode(record['value']))
            fail = fail or item.get('fail', False)
        except (ValueError, TypeError, UnicodeDecodeError):
            pass
    observation = {'request_id': context.aws_request_id, 'event': event, 'fail': fail and os.environ['FAIL'] == '1'}
    boto3.client('sqs', endpoint_url=os.environ['PROOF_ENDPOINT']).send_message(QueueUrl=os.environ['QUEUE_URL'], MessageBody=json.dumps(observation))
    if observation['fail']:
        raise RuntimeError('owned Kafka retry proof')
    return {'processed': len(values)}
'''


class LambdaProof(Proof):
    listen_host = '0.0.0.0'

    def __init__(self, args):
        super().__init__(args)
        self.functions = self.client('lambda')
        self.logs = self.client('logs')
        self.log_group = '/aws/lambda/' + self.prefix
        self.function = self.mapping = None
        self.group = self.prefix + '-lambda'

    def mapping_state(self, state):
        row = self.functions.get_event_source_mapping(UUID=self.mapping)
        return row if row['State'] == state else None

    def set_enabled(self, enabled):
        self.functions.update_event_source_mapping(UUID=self.mapping, Enabled=enabled)
        return self.wait(lambda: self.mapping_state('Enabled' if enabled else 'Disabled'), 'mapping transition')

    def function_ready(self):
        row = self.functions.get_function_configuration(FunctionName=self.function)
        return row if row['State'] == 'Active' and row.get('LastUpdateStatus', 'Successful') == 'Successful' else None

    def environment(self, fail):
        return {'Variables': {'FAIL': fail, 'PROOF_ENDPOINT': f'http://host.docker.internal:{self.port}',
                              'QUEUE_URL': self.queue.replace('127.0.0.1', 'host.docker.internal')}}

    def take(self, predicate):
        for row in self.receive() or []:
            if predicate(row):
                return row
        return None

    def capture_diagnostics(self):
        try:
            pages = self.logs.get_paginator('filter_log_events').paginate(
                logGroupName=self.log_group, PaginationConfig={'MaxItems': 1000})
            self.report['function_diagnostics'] = [event for page in pages for event in page.get('events', [])]
        except ClientError as error:
            self.report['diagnostic_error'] = error.response['Error']

    def cleanup(self):
        if self.mapping:
            self.functions.delete_event_source_mapping(UUID=self.mapping)
            self.wait(lambda: self.absent(self.functions, 'get_event_source_mapping', 'ResourceNotFoundException', UUID=self.mapping), 'mapping deletion')
            self.report['cleanup']['mapping'] = True
            self.mapping = None
        if self.function:
            self.functions.delete_function(FunctionName=self.function)
            require(self.absent(self.functions, 'get_function', 'ResourceNotFoundException', FunctionName=self.function), 'function remains')
            self.report['cleanup']['function'] = True
            self.function = None
        try:
            self.logs.delete_log_group(logGroupName=self.log_group)
        except ClientError as error:
            if error.response['Error']['Code'] != 'ResourceNotFoundException':
                raise
        self.report['cleanup']['function_logs'] = True
        super().cleanup()

    def authenticated_source(self):
        secrets, kms = self.client('secretsmanager'), self.client('kms')
        cluster = secret = key = mapping = None
        group = self.prefix + '-authenticated'
        password = uuid.uuid4().hex
        try:
            cluster = self.msk.create_cluster(ClusterName=self.prefix + '-auth', KafkaVersion='3.7.1', NumberOfBrokerNodes=1,
                BrokerNodeGroupInfo={'InstanceType': 'kafka.local', 'ClientSubnets': []},
                ClientAuthentication={'Sasl': {'Scram': {'Enabled': True}}},
                EncryptionInfo={'EncryptionInTransit': {'ClientBroker': 'TLS', 'InCluster': True}})['ClusterArn']
            self.wait(lambda: self.cluster(cluster), 'TLS/SCRAM source readiness', 240)
            key = kms.create_key(Policy=json.dumps({'Version': '2012-10-17', 'Statement': [
                {'Effect': 'Allow', 'Principal': {'AWS': 'arn:aws:iam::000000000000:root'}, 'Action': 'kms:*', 'Resource': '*'},
                {'Effect': 'Allow', 'Principal': {'Service': 'kafka.amazonaws.com'}, 'Action': 'kms:Decrypt', 'Resource': '*',
                 'Condition': {'ArnEquals': {'aws:SourceArn': cluster}}}]}))['KeyMetadata']['KeyId']
            secret = secrets.create_secret(Name='AmazonMSK_' + self.prefix, KmsKeyId=key,
                SecretString=json.dumps({'username': 'lambda-proof', 'password': password}))['ARN']
            result = self.msk.batch_associate_scram_secret(ClusterArn=cluster, SecretArnList=[secret])
            require(not result.get('UnprocessedScramSecrets'), 'native SCRAM secret association failed')
            self.wait(lambda: self.cluster(cluster), 'native SCRAM credentials', 240)
            with sqlite3.connect(self.state / 'msk.sqlite') as db:
                ca = db.execute('SELECT capem FROM msk_clusters WHERE arn=?', (cluster,)).fetchone()[0]
            settings = {'ARN': cluster, 'CAPEM': base64.b64encode(ca).decode(), 'Username': 'lambda-proof', 'Password': password}
            settings['Brokers'] = self.protocol('create', **settings)['bootstrap']
            self.iam.put_role_policy(RoleName=self.role, PolicyName='authenticated-source', PolicyDocument=json.dumps({'Version': '2012-10-17', 'Statement': [
                {'Effect': 'Allow', 'Action': ['kafka:DescribeClusterV2', 'kafka:GetBootstrapBrokers'], 'Resource': cluster},
                {'Effect': 'Allow', 'Action': 'secretsmanager:GetSecretValue', 'Resource': secret},
                {'Effect': 'Allow', 'Action': 'kms:Decrypt', 'Resource': '*'}]}))
            mapping = self.functions.create_event_source_mapping(FunctionName=self.function, EventSourceArn=cluster, Topics=[self.prefix],
                StartingPosition='TRIM_HORIZON', BatchSize=1, MaximumBatchingWindowInSeconds=0,
                AmazonManagedKafkaEventSourceConfig={'ConsumerGroupId': group},
                SourceAccessConfigurations=[{'Type': 'SASL_SCRAM_512_AUTH', 'URI': secret}])['UUID']
            self.wait(lambda: self.functions.get_event_source_mapping(UUID=mapping)['State'] == 'Enabled', 'SCRAM mapping')

            def committed(offset):
                rows = self.protocol('offsets', Group=group, **settings)['offsets'][self.prefix]
                return next((row['CommittedOffset'] for row in rows if row['Partition'] == 0), -1) == offset

            self.protocol('produce', Partition=0, Values=['{"id":"scram"}'], **settings)
            first = self.wait(lambda: self.take(lambda row: row['event']['eventSourceArn'] == cluster), 'real TLS/SCRAM Lambda invocation', 180)
            self.wait(lambda: committed(1), 'SCRAM successful offset')
            self.iam.put_role_policy(RoleName=self.role, PolicyName='deny-secret', PolicyDocument=json.dumps({'Version': '2012-10-17', 'Statement': [
                {'Effect': 'Deny', 'Action': 'secretsmanager:GetSecretValue', 'Resource': secret}]}))
            self.protocol('produce', Partition=0, Values=['{"id":"secret-denial"}'], **settings)
            time.sleep(3)
            require(committed(1) and self.receive() is None, 'secret denial consumed or acknowledged records')
            self.iam.delete_role_policy(RoleName=self.role, PolicyName='deny-secret')
            second = self.wait(lambda: self.take(lambda row: row['event']['eventSourceArn'] == cluster), 'current secret authority recovery', 180)
            self.wait(lambda: committed(2), 'secret authority offset')
            kms.disable_key(KeyId=key)
            self.protocol('produce', Partition=0, Values=['{"id":"kms-denial"}'], **settings)
            time.sleep(3)
            require(committed(2) and self.receive() is None, 'disabled KMS key consumed or acknowledged records')
            self.report['observations']['disabled_key_cluster'] = self.msk.describe_cluster(ClusterArn=cluster)['ClusterInfo']
            kms.enable_key(KeyId=key)
            third = self.wait(lambda: self.take(lambda row: row['event']['eventSourceArn'] == cluster), 'current KMS authority recovery', 180)
            self.wait(lambda: committed(3), 'KMS authority offset')
            self.report['observations']['scram_secret_kms'] = [first, second, third]
        finally:
            if mapping:
                self.functions.delete_event_source_mapping(UUID=mapping)
                self.wait(lambda: self.absent(self.functions, 'get_event_source_mapping', 'ResourceNotFoundException', UUID=mapping), 'SCRAM mapping deletion')
                self.report['cleanup']['scram_mapping'] = True
            if cluster:
                self.msk.delete_cluster(ClusterArn=cluster)
                self.wait(lambda: self.absent(self.msk, 'describe_cluster', 'NotFoundException', ClusterArn=cluster), 'SCRAM cluster deletion', 240)
                self.assert_native_absent(cluster, 'scram_')
            if secret:
                secrets.delete_secret(SecretId=secret, ForceDeleteWithoutRecovery=True)
                self.report['cleanup']['scram_secret'] = True
            if key:
                kms.schedule_key_deletion(KeyId=key, PendingWindowInDays=7)
                self.report['cleanup']['local_scram_key'] = 'PendingDeletion; no native AWS key created'

    def run(self):
        self.start()
        try:
            self.arn = self.msk.create_cluster(ClusterName=self.prefix, KafkaVersion='3.7.1', NumberOfBrokerNodes=1,
                BrokerNodeGroupInfo={'InstanceType': 'kafka.local', 'ClientSubnets': []},
                ClientAuthentication={'Unauthenticated': {'Enabled': True}},
                EncryptionInfo={'EncryptionInTransit': {'ClientBroker': 'PLAINTEXT', 'InCluster': True}})['ClusterArn']
            self.wait(self.cluster, 'actual Kafka broker readiness', 240)
            self.protocol('create')
            self.queue = self.sqs.create_queue(QueueName=self.prefix)['QueueUrl']
            queue_arn = self.sqs.get_queue_attributes(QueueUrl=self.queue, AttributeNames=['QueueArn'])['Attributes']['QueueArn']
            self.role = self.prefix
            role = self.iam.create_role(RoleName=self.role, AssumeRolePolicyDocument=json.dumps({'Version': '2012-10-17', 'Statement': [
                {'Effect': 'Allow', 'Principal': {'Service': 'lambda.amazonaws.com'}, 'Action': 'sts:AssumeRole'}]}))['Role']['Arn']
            self.iam.put_role_policy(RoleName=self.role, PolicyName='source-target', PolicyDocument=json.dumps({'Version': '2012-10-17', 'Statement': [
                {'Effect': 'Allow', 'Action': ['kafka:DescribeCluster', 'kafka:GetBootstrapBrokers'], 'Resource': self.arn},
                {'Effect': 'Allow', 'Action': 'sqs:SendMessage', 'Resource': queue_arn},
                {'Effect': 'Allow', 'Action': ['logs:CreateLogGroup', 'logs:CreateLogStream', 'logs:PutLogEvents'],
                 'Resource': 'arn:aws:logs:us-east-1:000000000000:log-group:' + self.log_group + ':*'}]}))
            package = io.BytesIO()
            with zipfile.ZipFile(package, 'w') as archive:
                archive.writestr('entry.py', HANDLER)
            self.function = self.prefix
            self.functions.create_function(FunctionName=self.function, Runtime='python3.12', Handler='entry.invoke', Role=role,
                Code={'ZipFile': package.getvalue()}, Timeout=20, MemorySize=128, Environment=self.environment('1'))
            self.wait(self.function_ready, 'real Lambda deployment')
            self.mapping = self.functions.create_event_source_mapping(FunctionName=self.function, EventSourceArn=self.arn, Topics=[self.prefix],
                StartingPosition='TRIM_HORIZON', BatchSize=3, MaximumBatchingWindowInSeconds=1,
                AmazonManagedKafkaEventSourceConfig={'ConsumerGroupId': self.group})['UUID']
            self.wait(lambda: self.mapping_state('Enabled'), 'mapping creation')
            timestamp = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=123000) - datetime.timedelta(minutes=1)
            timestamps = [timestamp + datetime.timedelta(seconds=i) for i in range(3)]
            records = [
                {'Key': base64.b64encode(b'key\x00').decode(), 'Value': base64.b64encode(b'{"id":"payload","kind":"keep"}').decode(), 'Headers': [{'Key': 'trace', 'Value': base64.b64encode(b'\x00\xff').decode()}, {'Key': 'trace', 'Value': ''}], 'Time': timestamps[0].isoformat()},
                {'Key': '', 'Value': base64.b64encode(b'\xff\x00binary').decode(), 'Time': timestamps[1].isoformat()},
                {'Key': None, 'Value': None, 'Time': timestamps[2].isoformat()}]
            self.protocol('produce', Partition=0, Records=records)
            observed = self.wait(lambda: self.take(lambda row: len(row['event']['records'].get(self.prefix+'-0', [])) == 3), 'native Lambda Kafka payload', 180)
            event = observed['event']
            native = event['records'][self.prefix+'-0']
            require(event['eventSource'] == 'aws:kafka' and event['eventSourceArn'] == self.arn and event['bootstrapServers'], 'Kafka envelope mismatch')
            require([r['offset'] for r in native] == [0, 1, 2] and all(r['partition'] == 0 and r['topic'] == self.prefix for r in native), 'partition/offset order mismatch')
            require(native[0]['key'] == records[0]['Key'] and native[0]['headers'] == [{'trace': [0, 255]}, {'trace': []}], 'binary key or duplicate headers changed')
            require(native[1]['value'] == records[1]['Value'] and native[2]['value'] is None and native[2]['key'] is None, 'binary/tombstone distinction lost')
            require([r['timestamp'] for r in native] == [int(stamp.timestamp() * 1000) for stamp in timestamps]
                    and all(r['timestampType'] == 'CREATE_TIME' for r in native), 'native timestamps changed')
            self.wait(lambda: self.offsets_committed(self.group, {0: 3}), 'successful native offset')
            self.report['observations']['payload'] = observed
            self.set_enabled(False)
            self.functions.update_event_source_mapping(UUID=self.mapping, BatchSize=2, MaximumBatchingWindowInSeconds=0,
                FilterCriteria={'Filters': [{'Pattern': json.dumps({'value': {'kind': ['keep']}})}]})
            self.wait(lambda: self.mapping_state('Disabled'), 'disabled update')
            self.protocol('produce', Partition=1, Values=['{"kind":"drop","id":"filtered"}', '{"kind":"keep","id":"retry","fail":true}'])
            time.sleep(2)
            require(self.receive() is None and self.offsets_committed(self.group, {1: 0}), 'disabled mapping consumed new records')
            self.controller.stop(timeout=60)
            self.start()
            self.wait(self.cluster, 'Kafka controller reopen', 240)
            require(self.mapping_state('Disabled'), 'disabled state lost after SQLite reopen')
            self.set_enabled(True)
            failed = self.wait(lambda: self.take(lambda row: row['fail']), 'actual runtime failure/retry', 180)
            require(self.offsets_committed(self.group, {1: 0}), 'function error advanced broker offset')
            repeated = self.wait(lambda: self.take(lambda row: row['fail'] and row['request_id'] != failed['request_id']), 'whole-batch repeated invocation', 180)
            require(repeated['event'] == failed['event'], 'retry changed native payload')
            self.report['observations']['failed_offset'] = self.offsets(self.group)
            self.report['observations']['retry'] = [failed, repeated]
            self.set_enabled(False)
            self.controller.stop(timeout=60)
            self.start()
            self.wait(self.cluster, 'failed-batch controller reopen', 240)
            self.functions.update_function_configuration(FunctionName=self.function, Environment=self.environment('0'))
            self.wait(self.function_ready, 'function configuration update')
            self.set_enabled(True)
            recovered = self.wait(lambda: self.take(lambda row: not row['fail'] and any(r['offset'] == 1 for r in row['event']['records'].get(self.prefix+'-1', []))), 'uncommitted batch recovery', 180)
            require(len(recovered['event']['records'][self.prefix+'-1']) == 1, 'filtered event was delivered')
            self.wait(lambda: self.offsets_committed(self.group, {0: 3, 1: 2}), 'recovered success-only commit')
            self.report['observations']['reopen'] = recovered
            self.iam.put_role_policy(RoleName=self.role, PolicyName='deny-source', PolicyDocument=json.dumps({'Version': '2012-10-17', 'Statement': [
                {'Effect': 'Deny', 'Action': 'kafka:GetBootstrapBrokers', 'Resource': self.arn}]}))
            self.protocol('produce', Partition=2, Values=['{"kind":"keep","id":"authority"}'])
            time.sleep(3)
            require(self.offsets_committed(self.group, {2: 0}), 'revoked source authority advanced offsets')
            self.iam.delete_role_policy(RoleName=self.role, PolicyName='deny-source')
            authorized = self.wait(lambda: self.take(lambda row: self.prefix+'-2' in row['event']['records']), 'current source-role authority recovery', 180)
            self.wait(lambda: self.offsets_committed(self.group, {2: 1}), 'authority recovery offset')
            self.report['observations']['current_role'] = authorized
            self.functions.update_function_configuration(FunctionName=self.function, Environment=self.environment('1'))
            self.wait(self.function_ready, 'retention-failure function configuration')
            self.protocol('produce', Partition=2, Values=['{"kind":"keep","id":"expire","fail":true}', '{"kind":"keep","id":"surviving"}'])
            expired_attempt = self.wait(lambda: self.take(lambda row: row['fail'] and self.prefix+'-2' in row['event']['records']), 'retention-pinned failed batch', 180)
            require(self.offsets_committed(self.group, {2: 1}), 'retention test acknowledged failed live records')
            truncated = self.protocol('truncate', Partition=2, Offset=2)
            require(truncated['first_offset'] == 2, 'native log start did not advance')
            surviving = self.wait(lambda: self.take(lambda row: not row['fail'] and [r['offset'] for r in row['event']['records'].get(self.prefix+'-2', [])] == [2]), 'surviving record after broker retention loss', 180)
            self.wait(lambda: self.offsets_committed(self.group, {2: 3}), 'retention recovery native commit')
            self.report['observations']['native_log_start_recovery'] = {'failed': expired_attempt, 'broker': truncated, 'surviving': surviving}
            self.protocol('delete')
            self.protocol('create')
            self.protocol('produce', Partition=0, Values=['{"kind":"keep","id":"replacement"}'])
            time.sleep(3)
            self.controller.stop(timeout=60)
            self.start()
            self.wait(self.cluster, 'incarnation-fenced reopen', 240)
            time.sleep(3)
            status = self.functions.get_event_source_mapping(UUID=self.mapping)
            require('source changed' in status.get('LastProcessingResult', '').lower(), 'replacement topic not fenced: '+str(status))
            require(self.receive() is None, 'replacement topic records were invoked')
            self.report['observations']['topic_incarnation'] = status['LastProcessingResult']
            self.msk.delete_cluster(ClusterArn=self.arn)
            self.wait(lambda: self.absent(self.msk, 'describe_cluster', 'NotFoundException', ClusterArn=self.arn), 'owned source deletion', 240)
            self.assert_native_absent(self.arn)
            self.arn = None
            self.functions.delete_event_source_mapping(UUID=self.mapping)
            self.wait(lambda: self.absent(self.functions, 'get_event_source_mapping', 'ResourceNotFoundException', UUID=self.mapping), 'mapping deletion after source loss')
            self.report['cleanup']['mapping_after_source_loss'] = True
            self.mapping = None
            self.authenticated_source()
        except Exception as error:
            self.report['failure'] = {'type': type(error).__name__, 'message': str(error)}
            self.capture_diagnostics()
            raise
        finally:
            try:
                if self.controller.process:
                    self.cleanup()
            finally:
                self.controller.stop(timeout=60)
                (self.state / 'lambda-msk-report.json').write_text(json.dumps(self.report, default=str, indent=2)+'\n')
        print(json.dumps({'report': str(self.state / 'lambda-msk-report.json'), 'observations': list(self.report['observations']), 'cleanup': self.report['cleanup']}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', required=True)
    parser.add_argument('--protocol-probe', required=True)
    parser.add_argument('--state-directory', required=True)
    parser.add_argument('--docker-host', default='unix:///var/run/docker.sock')
    parser.add_argument('--telemetry-directory', default='/home/r/dev/minor/stackd/bin')
    LambdaProof(parser.parse_args()).run()


if __name__ == '__main__':
    main()
