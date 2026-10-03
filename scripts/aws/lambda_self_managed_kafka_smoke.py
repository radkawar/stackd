#!/usr/bin/env python3
"""Signed self-managed Kafka -> real Lambda -> SQS, native offsets and restart.

The owned MSK runtime supplies a real broker only. The Lambda mapping receives
bootstrap addresses, never its ARN, and has an explicit kafka:* IAM deny.
"""
import argparse
import base64
import io
import json
from pathlib import Path
import sqlite3
import time
import uuid
import zipfile
import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

from lambda_msk_executable_smoke import LambdaProof, HANDLER
from msk_executable_smoke import require


class SelfManagedProof(LambdaProof):
    def __init__(self, args):
        super().__init__(args)
        self.secrets, self.kms = self.client('secretsmanager'), self.client('kms')
        self.secret = self.ca_secret = self.key = None
        self.protocol_security = {}

    def native(self, action, **kwargs):
        return self.protocol(action, **dict(self.protocol_security, **kwargs))

    def committed(self, offset):
        rows = self.native('offsets', Group=self.group)['offsets'][self.prefix]
        return next((row['CommittedOffset'] for row in rows if row['Partition'] == 0), -1) == offset

    def next_observation(self, identifier):
        return self.take(lambda row: any(json.loads(base64.b64decode(record['value'])).get('id') == identifier
                                        for records in row['event']['records'].values() for record in records))

    def legacy_async(self):
        event = {'records': {}, 'legacy_probe': self.prefix}
        payload = json.dumps(event).encode()
        version = self.functions.publish_version(FunctionName=self.function)['Version']
        response = self.functions.invoke_async(FunctionName=self.function + ':' + version, InvokeArgs=payload)
        require(response['Status'] == 202, 'legacy asynchronous invocation status')
        observed = self.wait(lambda: self.take(lambda row: row['event'] == event), 'legacy real Lambda external effect')
        for malformed, code in [(b'{', 'InvalidRequestContentException'),
                                (b'\"' + b'x' * (256 * 1024) + b'\"', 'RequestEntityTooLargeException')]:
            try:
                self.functions.invoke_async(FunctionName=self.function, InvokeArgs=malformed)
            except ClientError as error:
                require(error.response['Error']['Code'] == code, 'legacy request boundary')
            else:
                raise AssertionError('legacy invocation accepted invalid payload')
        name, key = self.prefix + '-legacy', None
        self.iam.create_user(UserName=name)
        try:
            key = self.iam.create_access_key(UserName=name)['AccessKey']
            caller = boto3.client('lambda', endpoint_url=self.endpoint, region_name='us-east-1',
                aws_access_key_id=key['AccessKeyId'], aws_secret_access_key=key['SecretAccessKey'],
                config=Config(retries={'total_max_attempts': 1}, read_timeout=90))
            function_arn = self.functions.get_function_configuration(FunctionName=self.function)['FunctionArn']
            for action, allowed in [('InvokeAsync', False), ('InvokeFunction', True)]:
                self.iam.put_user_policy(UserName=name, PolicyName='invoke', PolicyDocument=json.dumps({
                    'Version': '2012-10-17', 'Statement': [{'Effect': 'Allow', 'Action': 'lambda:' + action, 'Resource': function_arn}]}))
                try:
                    response = caller.invoke_async(FunctionName=self.function, InvokeArgs=payload)
                except ClientError as error:
                    require(not allowed and error.response['Error']['Code'] == 'AccessDeniedException', 'legacy native action authority')
                else:
                    require(allowed and response['Status'] == 202, 'legacy action incorrectly authorized')
                    self.wait(lambda: self.take(lambda row: row['event'] == event), 'authorized legacy external effect')
        finally:
            if key:
                self.iam.delete_access_key(UserName=name, AccessKeyId=key['AccessKeyId'])
            self.iam.delete_user_policy(UserName=name, PolicyName='invoke')
            self.iam.delete_user(UserName=name)
        self.report['observations']['legacy_invoke_async'] = {'version': version, 'effect': observed,
            'authority': 'InvokeFunction, not InvokeAsync', 'payload_limit': 256 * 1024}

    def cleanup(self):
        super().cleanup()
        for label, secret in [('credentials', self.secret), ('root_ca', self.ca_secret)]:
            if secret:
                self.secrets.delete_secret(SecretId=secret, ForceDeleteWithoutRecovery=True)
                require(self.absent(self.secrets, 'describe_secret', 'ResourceNotFoundException', SecretId=secret), label + ' secret remains')
                self.report['cleanup'][label] = True
        if self.key:
            self.kms.schedule_key_deletion(KeyId=self.key, PendingWindowInDays=7)
            self.report['cleanup']['local_key'] = 'PendingDeletion; no AWS native key exists'

    def setup(self, brokers=1):
        self.arn = self.msk.create_cluster(ClusterName=self.prefix, KafkaVersion='3.7.1', NumberOfBrokerNodes=brokers,
            BrokerNodeGroupInfo={'InstanceType': 'kafka.local', 'ClientSubnets': []},
            ClientAuthentication={'Sasl': {'Scram': {'Enabled': True}}},
            EncryptionInfo={'EncryptionInTransit': {'ClientBroker': 'TLS', 'InCluster': True}})['ClusterArn']
        self.wait(self.cluster, 'native TLS broker', 240)
        self.key = self.kms.create_key(Policy=json.dumps({'Version': '2012-10-17', 'Statement': [
            {'Effect': 'Allow', 'Principal': {'AWS': 'arn:aws:iam::000000000000:root'}, 'Action': 'kms:*', 'Resource': '*'},
            {'Effect': 'Allow', 'Principal': {'Service': 'kafka.amazonaws.com'}, 'Action': 'kms:Decrypt', 'Resource': '*',
             'Condition': {'ArnEquals': {'aws:SourceArn': self.arn}}}]}))['KeyMetadata']['KeyId']
        password = uuid.uuid4().hex
        self.secret = self.secrets.create_secret(Name='AmazonMSK_' + self.prefix, KmsKeyId=self.key,
            SecretString=json.dumps({'username': 'lambda-proof', 'password': password}))['ARN']
        associated = self.msk.batch_associate_scram_secret(ClusterArn=self.arn, SecretArnList=[self.secret])
        require(not associated.get('UnprocessedScramSecrets'), 'native SCRAM association failed')
        self.wait(self.cluster, 'native SCRAM credentials', 240)
        with sqlite3.connect(self.state / 'msk.sqlite') as db:
            ca = db.execute('SELECT capem FROM msk_clusters WHERE arn=?', (self.arn,)).fetchone()[0]
        self.ca_secret = self.secrets.create_secret(Name=self.prefix + '-ca', KmsKeyId=self.key,
            SecretString=json.dumps({'certificate': ca.decode()}))['ARN']
        self.protocol_security = {'CAPEM': base64.b64encode(ca).decode(), 'Username': 'lambda-proof', 'Password': password}
        self.native('create')
        self.queue = self.sqs.create_queue(QueueName=self.prefix)['QueueUrl']
        queue_arn = self.sqs.get_queue_attributes(QueueUrl=self.queue, AttributeNames=['QueueArn'])['Attributes']['QueueArn']
        self.role = self.prefix
        role = self.iam.create_role(RoleName=self.role, AssumeRolePolicyDocument=json.dumps({'Version': '2012-10-17', 'Statement': [
            {'Effect': 'Allow', 'Principal': {'Service': 'lambda.amazonaws.com'}, 'Action': 'sts:AssumeRole'}]}))['Role']['Arn']
        self.iam.put_role_policy(RoleName=self.role, PolicyName='source-target', PolicyDocument=json.dumps({'Version': '2012-10-17', 'Statement': [
            {'Effect': 'Allow', 'Action': 'sqs:SendMessage', 'Resource': queue_arn},
            {'Effect': 'Allow', 'Action': 'secretsmanager:GetSecretValue', 'Resource': [self.secret, self.ca_secret]},
            {'Effect': 'Allow', 'Action': 'kms:Decrypt', 'Resource': '*'},
            {'Effect': 'Allow', 'Action': ['logs:CreateLogGroup', 'logs:CreateLogStream', 'logs:PutLogEvents'], 'Resource': '*'},
            {'Effect': 'Deny', 'Action': 'kafka:*', 'Resource': '*'}]}))
        package = io.BytesIO()
        with zipfile.ZipFile(package, 'w') as archive:
            archive.writestr('entry.py', HANDLER)
        self.function = self.prefix
        self.functions.create_function(FunctionName=self.function, Runtime='python3.12', Handler='entry.invoke', Role=role,
            Code={'ZipFile': package.getvalue()}, Timeout=20, MemorySize=128, Environment=self.environment('1'))
        self.wait(self.function_ready, 'real function ready')

    def run(self):
        self.start()
        try:
            self.setup()
            self.legacy_async()
            brokers = self.msk.get_bootstrap_brokers(ClusterArn=self.arn)['BootstrapBrokerStringSaslScram'].split(',')
            config = dict(FunctionName=self.function, Topics=[self.prefix], StartingPosition='TRIM_HORIZON', BatchSize=1,
                MaximumBatchingWindowInSeconds=0, SelfManagedEventSource={'Endpoints': {'KAFKA_BOOTSTRAP_SERVERS': brokers}},
                SelfManagedKafkaEventSourceConfig={'ConsumerGroupId': self.group},
                SourceAccessConfigurations=[{'Type': 'SASL_SCRAM_512_AUTH', 'URI': self.secret},
                                            {'Type': 'SERVER_ROOT_CA_CERTIFICATE', 'URI': self.ca_secret}])
            self.mapping = self.functions.create_event_source_mapping(**config)['UUID']
            self.wait(lambda: self.mapping_state('Enabled'), 'self-managed mapping ready')
            projected = self.functions.get_event_source_mapping(UUID=self.mapping)
            require('EventSourceArn' not in projected and projected['SelfManagedEventSource']['Endpoints']['KAFKA_BOOTSTRAP_SERVERS'] == sorted(brokers), 'self-managed configuration envelope')
            foreign = self.client('lambda', key='222222222222')
            try:
                foreign.get_event_source_mapping(UUID=self.mapping)
            except Exception as error:
                require(getattr(error, 'response', {}).get('Error', {}).get('Code') in ('ResourceNotFoundException', 'AccessDeniedException'), 'unexpected isolation error')
            else:
                raise AssertionError('foreign account can read mapping')
            self.native('produce', Partition=0, Values=['{"id":"first"}'])
            first = self.wait(lambda: self.next_observation('first'), 'real self-managed Kafka Lambda effect', 180)
            require(first['event']['eventSource'] == 'SelfManagedKafka' and 'eventSourceArn' not in first['event'], 'self-managed event envelope differs')
            self.wait(lambda: self.committed(1), 'successful broker checkpoint')
            self.native('produce', Partition=0, Values=['{"id":"retry","fail":true}'])
            failed = self.wait(lambda: self.next_observation('retry'), 'failed runtime effect', 180)
            require(failed['fail'] and self.committed(1), 'failed invocation acknowledged')
            self.controller.stop(timeout=60)
            self.start()
            self.wait(self.cluster, 'source bytes retained on controller restart', 240)
            self.functions.update_function_configuration(FunctionName=self.function, Environment=self.environment('0'))
            self.wait(self.function_ready, 'runtime update recovery')
            recovered = self.wait(lambda: self.take(lambda row: not row['fail'] and any(json.loads(base64.b64decode(r['value'])).get('id') == 'retry' for rows in row['event']['records'].values() for r in rows)), 'retry after restart', 180)
            self.wait(lambda: self.committed(2), 'recovered broker checkpoint')
            while self.receive():
                pass
            self.iam.put_role_policy(RoleName=self.role, PolicyName='deny-ca', PolicyDocument=json.dumps({'Version': '2012-10-17', 'Statement': [
                {'Effect': 'Deny', 'Action': 'secretsmanager:GetSecretValue', 'Resource': self.ca_secret}]}))
            self.native('produce', Partition=0, Values=['{"id":"ca-denied"}'])
            time.sleep(3)
            require(self.committed(2) and self.receive() is None, 'revoked CA secret authority consumed records')
            self.iam.delete_role_policy(RoleName=self.role, PolicyName='deny-ca')
            ca_restored = self.wait(lambda: self.next_observation('ca-denied'), 'current CA secret authority recovery', 180)
            self.wait(lambda: self.committed(3), 'CA authority checkpoint')
            self.kms.disable_key(KeyId=self.key)
            self.native('produce', Partition=0, Values=['{"id":"kms-denied"}'])
            time.sleep(3)
            require(self.committed(3) and self.receive() is None, 'disabled KMS key consumed records')
            self.kms.enable_key(KeyId=self.key)
            kms_restored = self.wait(lambda: self.next_observation('kms-denied'), 'current KMS authority recovery', 180)
            self.wait(lambda: self.committed(4), 'KMS authority checkpoint')
            self.set_enabled(False)
            self.functions.update_event_source_mapping(UUID=self.mapping, FilterCriteria={'Filters': [{'Pattern': '{"value":{"kind":["keep"]}}'}]})
            self.wait(lambda: self.mapping_state('Disabled'), 'filter update')
            self.native('produce', Partition=0, Values=['{"id":"filtered","kind":"drop"}', '{"id":"matched","kind":"keep"}'])
            self.set_enabled(True)
            matched = self.wait(lambda: self.next_observation('matched'), 'Kafka value filtering', 180)
            self.wait(lambda: self.committed(6), 'filtered and delivered offsets')
            self.controller.stop(timeout=60)
            self.start()
            self.wait(self.cluster, 'second controller recovery', 240)
            time.sleep(3)
            require(self.committed(6) and self.receive() is None, 'acknowledged records replay after restart')
            self.report['observations'].update({'configuration': projected, 'first': first, 'failed': failed, 'restart_recovery': recovered,
                'ca_authority_recovery': ca_restored, 'kms_authority_recovery': kms_restored, 'filter_match': matched,
                'final_native_offset': 6, 'source_control_authority': 'function role explicitly denies kafka:*'})
        finally:
            try:
                if self.controller.process is not None:
                    self.cleanup()
            finally:
                self.controller.stop(timeout=60)
                (self.state / 'lambda-self-managed-kafka-report.json').write_text(json.dumps(self.report, default=str, indent=2) + '\n')
        print(json.dumps({'report': str(self.state / 'lambda-self-managed-kafka-report.json'), 'cleanup': self.report['cleanup']}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', required=True)
    parser.add_argument('--protocol-probe', required=True)
    parser.add_argument('--state-directory', required=True)
    parser.add_argument('--docker-host', default='unix:///var/run/docker.sock')
    parser.add_argument('--telemetry-directory', default='/home/r/dev/minor/stackd/bin')
    SelfManagedProof(parser.parse_args()).run()


if __name__ == '__main__':
    main()
