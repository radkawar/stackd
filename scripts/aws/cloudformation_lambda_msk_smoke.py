#!/usr/bin/env python3
"""Signed CFN -> actual MSK TLS/SCRAM broker -> official Python Lambda -> SQS.

Requires built stackd, msk_protocol_probe, Lambda telemetry binaries, Docker,
and the existing proof's preloaded Kafka/Python Lambda images. Uses a fresh
local SQLite directory and explicit local SDK endpoints, never ambient AWS.
Reports local executable behavior; these observations are not native AWS evidence.
"""
import argparse
import base64
import copy
import datetime
import io
import json
import shlex
import sqlite3
import sys
import time
import uuid
import zipfile

from botocore.exceptions import ClientError

from lambda_msk_executable_smoke import HANDLER, LambdaProof
from msk_executable_smoke import require


class CloudFormationMSKProof(LambdaProof):
    def __init__(self, args):
        super().__init__(args)
        self.cfn = self.client('cloudformation')
        self.secrets, self.kms = self.client('secretsmanager'), self.client('kms')
        self.secret = self.key = self.stack = self.properties = None
        self.protocol_security = {}
        self.topic = self.prefix
        self.effects = []
        self.report_path = self.state / 'cloudformation-lambda-msk-report.json'
        self.report['command'] = shlex.join([sys.executable, *sys.argv])
        self.report['scope'] = 'Local executable integration; not native AWS lifecycle evidence'

    def receive(self):
        rows = super().receive()
        if rows:
            self.effects.extend(rows)
        return rows

    def native(self, action, **kwargs):
        return self.protocol(action, **dict(self.protocol_security, Topic=self.topic, **kwargs))

    def committed(self, offset):
        rows = self.native('offsets', Group=self.group)['offsets'][self.topic]
        return next((row['CommittedOffset'] for row in rows if row['Partition'] == 0), -1) == offset

    def checkpoint(self, offset):
        self.wait(lambda: self.committed(offset), 'native broker checkpoint ' + str(offset))

    def quiet(self, offset, label):
        time.sleep(3)
        require(self.committed(offset) and self.receive() is None, label)

    def quiet_before_first_delivery(self, label):
        # Disabled admission does not join/create a broker group. Each caller
        # subsequently requires offset-zero delivery to prove backlog retention.
        time.sleep(3)
        require(self.receive() is None, label)

    def setup(self, create_topic=True):
        config = self.msk.create_configuration(Name=self.prefix, KafkaVersions=['3.7.1'],
            ServerProperties=b'auto.create.topics.enable=false\nnum.partitions=3\nlog.retention.ms=86400000\n')
        self.config_arn = config['Arn']
        self.arn = self.msk.create_cluster(ClusterName=self.prefix, KafkaVersion='3.7.1', NumberOfBrokerNodes=1,
            BrokerNodeGroupInfo={'InstanceType': 'kafka.local', 'ClientSubnets': []},
            ClientAuthentication={'Sasl': {'Scram': {'Enabled': True}}},
            EncryptionInfo={'EncryptionInTransit': {'ClientBroker': 'TLS', 'InCluster': True}},
            ConfigurationInfo={'Arn': self.config_arn, 'Revision': config['LatestRevision']['Revision']})['ClusterArn']
        self.wait(self.cluster, 'actual MSK TLS broker', 240)
        self.key = self.kms.create_key(Policy=json.dumps({'Version': '2012-10-17', 'Statement': [
            {'Effect': 'Allow', 'Principal': {'AWS': 'arn:aws:iam::000000000000:root'}, 'Action': 'kms:*', 'Resource': '*'},
            {'Effect': 'Allow', 'Principal': {'Service': 'kafka.amazonaws.com'}, 'Action': 'kms:Decrypt', 'Resource': '*',
             'Condition': {'ArnEquals': {'aws:SourceArn': self.arn}}}]}))['KeyMetadata']['KeyId']
        password = uuid.uuid4().hex
        self.secret = self.secrets.create_secret(Name='AmazonMSK_' + self.prefix, KmsKeyId=self.key,
            SecretString=json.dumps({'username': 'lambda-proof', 'password': password}))['ARN']
        associated = self.msk.batch_associate_scram_secret(ClusterArn=self.arn, SecretArnList=[self.secret])
        require(not associated.get('UnprocessedScramSecrets'), 'MSK SCRAM association failed')
        self.wait(self.cluster, 'actual MSK SCRAM credentials', 240)
        # The independent protocol client needs the owned local broker's CA.
        # Lambda itself resolves source credentials through MSK/Secrets/KMS.
        with sqlite3.connect(self.state / 'msk.sqlite') as db:
            ca = db.execute('SELECT capem FROM msk_clusters WHERE arn=?', (self.arn,)).fetchone()[0]
        self.protocol_security = {'CAPEM': base64.b64encode(ca).decode(), 'Username': 'lambda-proof', 'Password': password}
        if create_topic:
            self.native('create')
        self.report['observations']['broker_metadata'] = self.native('metadata')
        self.queue = self.sqs.create_queue(QueueName=self.prefix)['QueueUrl']
        queue_arn = self.sqs.get_queue_attributes(QueueUrl=self.queue, AttributeNames=['QueueArn'])['Attributes']['QueueArn']
        self.role = self.prefix
        role = self.iam.create_role(RoleName=self.role, AssumeRolePolicyDocument=json.dumps({'Version': '2012-10-17', 'Statement': [
            {'Effect': 'Allow', 'Principal': {'Service': 'lambda.amazonaws.com'}, 'Action': 'sts:AssumeRole'}]}))['Role']['Arn']
        self.iam.put_role_policy(RoleName=self.role, PolicyName='source-target', PolicyDocument=json.dumps({'Version': '2012-10-17', 'Statement': [
            {'Effect': 'Allow', 'Action': ['kafka:DescribeCluster', 'kafka:DescribeClusterV2', 'kafka:GetBootstrapBrokers'], 'Resource': self.arn},
            {'Effect': 'Allow', 'Action': 'secretsmanager:GetSecretValue', 'Resource': self.secret},
            {'Effect': 'Allow', 'Action': 'kms:Decrypt', 'Resource': '*'},
            {'Effect': 'Allow', 'Action': 'sqs:SendMessage', 'Resource': queue_arn},
            {'Effect': 'Allow', 'Action': ['logs:CreateLogGroup', 'logs:CreateLogStream', 'logs:PutLogEvents'],
             'Resource': 'arn:aws:logs:us-east-1:000000000000:log-group:' + self.log_group + ':*'}]}))
        package = io.BytesIO()
        with zipfile.ZipFile(package, 'w') as archive:
            archive.writestr('entry.py', HANDLER)
        self.function = self.prefix
        self.functions.create_function(FunctionName=self.function, Runtime='python3.12', Handler='entry.invoke', Role=role,
            Code={'ZipFile': package.getvalue()}, Timeout=20, MemorySize=128, Environment=self.environment('1'))
        self.wait(self.function_ready, 'official Python Lambda deployment')

    def template(self, properties):
        return {'AWSTemplateFormatVersion': '2010-09-09', 'Resources': {
            'Mapping': {'Type': 'AWS::Lambda::EventSourceMapping', 'Properties': properties}},
            'Outputs': {'MappingUUID': {'Value': {'Ref': 'Mapping'}},
                        'MappingId': {'Value': {'Fn::GetAtt': ['Mapping', 'Id']}},
                        'MappingArn': {'Value': {'Fn::GetAtt': ['Mapping', 'EventSourceMappingArn']}}}}

    def stack_ready(self, expected):
        row = self.cfn.describe_stacks(StackName=self.stack)['Stacks'][0]
        status = row['StackStatus']
        if status == expected:
            return row
        if expected == 'UPDATE_ROLLBACK_COMPLETE' and status in (
                'UPDATE_ROLLBACK_IN_PROGRESS', 'UPDATE_ROLLBACK_COMPLETE_CLEANUP_IN_PROGRESS'):
            return None
        if 'FAILED' in status or 'ROLLBACK' in status or status.endswith('_COMPLETE'):
            events = self.cfn.describe_stack_events(StackName=self.stack)['StackEvents']
            raise AssertionError('CloudFormation ' + status + ': ' + json.dumps(events, default=str))
        return None

    def projection(self, stack):
        outputs = {row['OutputKey']: row['OutputValue'] for row in stack['Outputs']}
        identifier = outputs['MappingUUID']
        require(str(uuid.UUID(identifier)) == identifier, 'CFN Ref is not a mapping UUID')
        require(outputs['MappingId'] == identifier, 'CFN Id and Ref differ')
        mapping = self.functions.get_event_source_mapping(UUID=identifier)
        require(outputs['MappingArn'] == mapping['EventSourceMappingArn'], 'CFN ARN does not identify the live mapping')
        require(mapping['EventSourceArn'] == self.arn and 'SelfManagedEventSource' not in mapping,
                'MSK mapping lost its cluster source or acquired self-managed bootstrap settings')
        resource = self.cfn.describe_stack_resource(StackName=self.stack, LogicalResourceId='Mapping')['StackResourceDetail']
        require(resource['PhysicalResourceId'] == identifier, 'stack resource and Lambda mapping identity differ')
        tags = self.functions.list_tags(Resource=outputs['MappingArn']).get('Tags', {})
        require(tags.get('proof') == self.prefix, 'stack-owned mapping tag was not applied')
        return identifier, mapping, outputs

    def deploy(self, label, position='TRIM_HORIZON'):
        self.properties = {'FunctionName': self.function, 'EventSourceArn': self.arn,
            'Enabled': False, 'Topics': [self.topic], 'BatchSize': 1,
            'AmazonManagedKafkaEventSourceConfig': {'ConsumerGroupId': self.group},
            'SourceAccessConfigurations': [{'Type': 'SASL_SCRAM_512_AUTH', 'URI': self.secret}],
            'Tags': [{'Key': 'proof', 'Value': self.prefix}]}
        if position is not None:
            self.properties['StartingPosition'] = position
        self.stack = self.prefix + '-' + label
        self.cfn.create_stack(StackName=self.stack, TemplateBody=json.dumps(self.template(self.properties)))
        stack = self.wait(lambda: self.stack_ready('CREATE_COMPLETE'), 'CFN ' + label + ' creation', 240)
        self.mapping, mapping, outputs = self.projection(stack)
        require(mapping['AmazonManagedKafkaEventSourceConfig']['ConsumerGroupId'] == self.group,
                'CFN did not use the configured MSK consumer group')
        if position is not None:
            require(mapping['StartingPosition'] == position, 'configured MSK starting position changed')
        self.wait(lambda: self.mapping_state('Disabled'), 'initial disabled mapping')
        self.report['observations'][label + '-creation'] = {'mapping': mapping, 'outputs': outputs}
        return mapping

    def update(self, label, remove=(), **changes):
        properties = copy.deepcopy(self.properties)
        properties.update(changes)
        for name in remove:
            properties.pop(name, None)
        self.cfn.update_stack(StackName=self.stack, TemplateBody=json.dumps(self.template(properties)))
        stack = self.wait(lambda: self.stack_ready('UPDATE_COMPLETE'), 'CFN ' + label, 240)
        self.properties = properties
        identifier, mapping, outputs = self.projection(stack)
        require(identifier == self.mapping, label + ' replaced a mutable mapping')
        self.wait(lambda: self.mapping_state('Enabled' if properties.get('Enabled', True) else 'Disabled'), label)
        self.report['observations'][label] = {'mapping': mapping, 'outputs': outputs}
        return mapping

    def produce(self, identifier, **fields):
        self.native('produce', Partition=0, Values=[json.dumps({'id': identifier, **fields})])

    @staticmethod
    def record_id(record):
        try:
            value = json.loads(base64.b64decode(record['value']))
            return value.get('id') if isinstance(value, dict) else None
        except (ValueError, TypeError, UnicodeDecodeError):
            return None

    def delivered(self, identifier, offset, failed=False):
        row = self.wait(lambda: self.take(lambda value: value['fail'] == failed and any(
            self.record_id(record) == identifier
            for records in value['event']['records'].values() for record in records)),
            'official Python runtime effect for ' + identifier, 180)
        event = row['event']
        require(event['eventSource'] == 'aws:kafka' and event['eventSourceArn'] == self.arn and event['bootstrapServers'],
                'incorrect MSK Kafka event envelope')
        record = next(record for records in event['records'].values() for record in records
                      if self.record_id(record) == identifier)
        require(record['topic'] == self.topic and record['partition'] == 0 and record['offset'] == offset,
                'broker offset/topic/partition did not reach the Python runtime')
        require(row['request_id'], 'official Lambda runtime did not provide request identity')
        self.report['observations'][identifier] = row
        return row

    def observed_ids(self):
        return [self.record_id(record) for row in self.effects
                for records in row['event']['records'].values() for record in records]

    def restart(self, offset, retained_id):
        self.controller.stop(timeout=60)
        self.start()
        self.wait(self.cluster, 'actual MSK broker recovery after SQLite reopen', 240)
        stack = self.wait(lambda: self.stack_ready('UPDATE_COMPLETE'), 'durable stack recovery')
        require(self.projection(stack)[0] == self.mapping, 'stack/mapping identity changed after SQLite reopen')
        require(self.committed(offset), 'controller restart lost the broker-owned group offset')
        retained = self.native('read', Partition=0, Offset=offset)
        require(json.loads(retained['value'])['id'] == retained_id and retained['offset'] == offset,
                'controller restart lost actual broker bytes')
        self.report['observations'][retained_id + '-retained-broker-bytes'] = retained

    def group_change_plan(self, offset):
        properties = copy.deepcopy(self.properties)
        properties['AmazonManagedKafkaEventSourceConfig'] = {'ConsumerGroupId': self.group + '-planned'}
        change = self.cfn.create_change_set(StackName=self.stack, ChangeSetName=self.prefix + '-group-plan',
            ChangeSetType='UPDATE', TemplateBody=json.dumps(self.template(properties)))['Id']
        try:
            def ready():
                row = self.cfn.describe_change_set(ChangeSetName=change)
                require(row['Status'] != 'FAILED', 'group change-set creation failed: ' + json.dumps(row, default=str))
                return row if row['Status'] == 'CREATE_COMPLETE' else None
            plan = self.wait(ready, 'unexecuted group change-set plan')
            resource = next(row['ResourceChange'] for row in plan['Changes']
                            if row['ResourceChange']['LogicalResourceId'] == 'Mapping')
            require(resource['Action'] == 'Modify' and resource['Replacement'] == 'False',
                    'group change-set public plan differs from measured native nonreplacement projection')
            target = next(row['Target'] for row in resource['Details']
                          if row['Target'].get('Name') == 'AmazonManagedKafkaEventSourceConfig')
            require(target['RequiresRecreation'] == 'Never',
                    'group plan recreation differs from measured native public metadata')
            mapping = self.functions.get_event_source_mapping(UUID=self.mapping)
            require(mapping['AmazonManagedKafkaEventSourceConfig']['ConsumerGroupId'] == self.group
                    and self.committed(offset), 'unexecuted change set altered live mapping or checkpoint')
            self.report['observations']['group-change-set'] = {'executed': False, 'description': plan}
        finally:
            self.cfn.delete_change_set(ChangeSetName=change)
            self.wait(lambda: self.absent(self.cfn, 'describe_change_set', 'ChangeSetNotFound', ChangeSetName=change),
                      'owned unexecuted change-set deletion')
            self.report['cleanup']['group_change_set'] = True

    def immutable_transition(self, label, offset, remove=(), verify_delivery=True, **changes):
        properties = copy.deepcopy(self.properties)
        properties.update(changes)
        for name in remove:
            properties.pop(name, None)
        self.cfn.update_stack(StackName=self.stack, TemplateBody=json.dumps(self.template(properties)))
        stack = self.wait(lambda: self.stack_ready('UPDATE_ROLLBACK_COMPLETE'), label + ' rollback', 240)
        identifier, mapping, outputs = self.projection(stack)
        require(identifier == self.mapping
                and mapping['AmazonManagedKafkaEventSourceConfig']['ConsumerGroupId'] == self.group
                and mapping['Topics'] == [self.topic], 'failed CFN transition changed the original mapping/group/topic')
        require(self.committed(offset), 'failed CFN transition changed the broker checkpoint')
        if verify_delivery:
            self.produce(label)
            self.delivered(label, offset)
            offset += 1
            self.checkpoint(offset)
        self.report['observations'][label + '-rollback'] = {
            'stack_status': stack['StackStatus'], 'mapping': mapping, 'outputs': outputs,
            'events': self.cfn.describe_stack_events(StackName=self.stack)['StackEvents']}
        return offset

    def payload(self):
        self.update('payload-batch', BatchSize=3, MaximumBatchingWindowInSeconds=1)
        timestamp = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=123000) - datetime.timedelta(minutes=1)
        timestamps = [timestamp + datetime.timedelta(seconds=index) for index in range(3)]
        records = [
            {'Key': base64.b64encode(b'key\x00').decode(),
             'Value': base64.b64encode(b'{"id":"binary-payload","kind":"keep"}').decode(),
             'Headers': [{'Key': 'trace', 'Value': base64.b64encode(b'\x00\xff').decode()}, {'Key': 'trace', 'Value': ''}],
             'Time': timestamps[0].isoformat()},
            {'Key': '', 'Value': base64.b64encode(b'\xff\x00binary').decode(), 'Time': timestamps[1].isoformat()},
            {'Key': None, 'Value': None, 'Time': timestamps[2].isoformat()}]
        self.native('produce', Partition=0, Records=records)
        self.quiet_before_first_delivery('disabled CFN mapping delivered actual broker backlog')
        self.update('enabled-backlog', Enabled=True)
        observed = self.delivered('binary-payload', 0)
        native = observed['event']['records'][self.topic + '-0']
        require([record['offset'] for record in native] == [0, 1, 2], 'broker batch offsets changed')
        require(native[0]['key'] == records[0]['Key'] and native[0]['headers'] == [{'trace': [0, 255]}, {'trace': []}],
                'binary key or duplicate binary headers changed')
        require(native[1]['value'] == records[1]['Value'] and native[2]['value'] is None and native[2]['key'] is None,
                'binary/tombstone distinction lost')
        require([record['timestamp'] for record in native] == [int(stamp.timestamp() * 1000) for stamp in timestamps]
                and all(record['timestampType'] == 'CREATE_TIME' for record in native), 'broker timestamps changed')
        self.checkpoint(3)

    def exercise(self):
        self.payload()
        self.update('filter-added', Enabled=False, BatchSize=2, MaximumBatchingWindowInSeconds=1,
                    FilterCriteria={'Filters': [{'Pattern': '{"value":{"kind":["keep"]}}'}]})
        self.produce('filtered-out', kind='drop')
        self.produce('filter-match', kind='keep')
        self.quiet(3, 'disabled filtered mapping consumed backlog')
        self.update('filter-enabled', Enabled=True)
        self.delivered('filter-match', 4)
        self.checkpoint(5)
        require('filtered-out' not in self.observed_ids(), 'filter delivered a rejected Kafka record')
        self.update('settings-disabled', Enabled=False)
        removed = self.update('settings-removed', remove=(
            'Enabled', 'FilterCriteria', 'BatchSize', 'MaximumBatchingWindowInSeconds', 'SourceAccessConfigurations'))
        require(removed['BatchSize'] == 100 and removed['MaximumBatchingWindowInSeconds'] == 1
                and not removed.get('FilterCriteria'),
                'MSK settings omission differs from measured native batch reset/window retention/filter clearing')
        self.produce('settings-removal-delivery', kind='drop')
        self.delivered('settings-removal-delivery', 5)
        self.checkpoint(6)
        self.update('runtime-controls-restored', Enabled=True, BatchSize=1, MaximumBatchingWindowInSeconds=0,
                    SourceAccessConfigurations=[{'Type': 'SASL_SCRAM_512_AUTH', 'URI': self.secret}])

        offset = 6
        for label, action, resource in [('source-iam-recovery', 'kafka:GetBootstrapBrokers', self.arn),
                                        ('secret-iam-recovery', 'secretsmanager:GetSecretValue', self.secret)]:
            self.iam.put_role_policy(RoleName=self.role, PolicyName='deny-current', PolicyDocument=json.dumps({
                'Version': '2012-10-17', 'Statement': [{'Effect': 'Deny', 'Action': action, 'Resource': resource}]}))
            try:
                self.produce(label)
                self.quiet(offset, 'current IAM denial consumed or acknowledged a record: ' + action)
                self.report['observations'][label + '-denied-offsets'] = self.native('offsets', Group=self.group)
            finally:
                self.iam.delete_role_policy(RoleName=self.role, PolicyName='deny-current')
            self.delivered(label, offset)
            offset += 1
            self.checkpoint(offset)

        self.produce('restart-retry', fail=True)
        self.delivered('restart-retry', offset, failed=True)
        require(self.committed(offset), 'failed official Python invocation acknowledged its broker offset')
        self.update('retry-disabled', Enabled=False)
        self.restart(offset, 'restart-retry')
        require(self.mapping_state('Disabled'), 'disabled mapping state lost after SQLite reopen')
        while self.receive():
            pass
        self.functions.update_function_configuration(FunctionName=self.function, Environment=self.environment('0'))
        self.wait(self.function_ready, 'runtime recovery configuration')
        version = self.functions.publish_version(FunctionName=self.function)['Version']
        # The qualified target must retain its snapshot, not invoke $LATEST.
        self.functions.update_function_configuration(FunctionName=self.function, Environment=self.environment('1'))
        self.wait(self.function_ready, 'latest configuration diverges from published version')
        self.update('version-target', FunctionName=self.function + ':' + version, Enabled=True)
        self.delivered('restart-retry', offset)
        offset += 1
        self.checkpoint(offset)
        self.functions.create_alias(FunctionName=self.function, Name='live', FunctionVersion=version)
        self.update('alias-target', FunctionName=self.function + ':live')
        self.produce('alias-delivery', fail=True)
        self.delivered('alias-delivery', offset)
        offset += 1
        self.checkpoint(offset)
        self.update('restart-disabled', Enabled=False)
        while self.receive():
            pass
        self.produce('post-restart')
        self.restart(offset, 'post-restart')
        self.quiet(offset, 'disabled retained mapping advanced after executable restart')
        self.update('restart-enabled', Enabled=True)
        self.delivered('post-restart', offset)
        offset += 1
        self.checkpoint(offset)
        require(self.observed_ids().count('alias-delivery') == 1, 'acknowledged qualified-target record replayed after restart')
        self.group_change_plan(offset)
        offset = self.immutable_transition('group-change', offset,
            AmazonManagedKafkaEventSourceConfig={'ConsumerGroupId': self.group + '-changed'})
        offset = self.immutable_transition('group-removal', offset, remove=('AmazonManagedKafkaEventSourceConfig',))
        offset = self.immutable_transition('topic-change', offset, Topics=[self.topic + '-other'])
        offset = self.immutable_transition('topic-removal', offset, remove=('Topics',))
        self.report['observations']['final_native_offset'] = offset
        self.delete_stack('configured', offset)

    def default_position(self):
        self.topic = self.prefix + '-default'
        self.group = self.prefix + '-default-group'
        self.native('create')
        self.produce('default-position-backlog')
        mapping = self.deploy('default-position', position=None)
        require(mapping['StartingPosition'] == 'TRIM_HORIZON',
                'omitted MSK position differs from the measured native CFN TRIM_HORIZON default')
        require('MaximumBatchingWindowInSeconds' not in mapping,
                'default 500ms Kafka window was incorrectly projected as integer seconds')
        self.report['observations']['default-starting-position'] = mapping.get('StartingPosition')
        self.quiet_before_first_delivery('default-position disabled mapping delivered pre-creation backlog')
        self.update('default-position-enabled', Enabled=True)
        self.delivered('default-position-backlog', 0)
        self.checkpoint(1)
        self.delete_stack('default-position', 1)

    def late_topic(self):
        self.topic = self.prefix + '-late-topic'
        self.group = self.prefix + '-late-topic-group'
        metadata = self.native('metadata')
        topic = next(row for row in metadata['metadata']['Topics'] if row['Name'] == self.topic)
        require(topic['Error'] == 3 and not topic['Partitions'],
                'late-topic proof requires an absent topic with automatic broker creation disabled')
        self.report['observations']['late-topic-absent-before-deployment'] = metadata
        self.deploy('late-topic')
        require(self.mapping_state('Disabled'), 'absent-topic mapping did not remain disabled')
        self.native('create')
        self.report['observations']['late-topic-created-after-deployment'] = self.native('metadata')
        self.produce('late-topic-backlog')
        self.quiet_before_first_delivery('disabled late-topic mapping delivered backlog')
        self.update('late-topic-enabled', Enabled=True)
        self.delivered('late-topic-backlog', 0)
        self.checkpoint(1)
        self.update('late-topic-restart-disabled', Enabled=False)
        self.produce('late-topic-post-restart')
        self.restart(1, 'late-topic-post-restart')
        require(self.mapping_state('Disabled'), 'late-topic disabled mapping state lost after SQLite reopen')
        self.quiet(1, 'late-topic mapping advanced or replayed its checkpoint after restart')
        self.update('late-topic-restart-enabled', Enabled=True)
        self.delivered('late-topic-post-restart', 1)
        self.checkpoint(2)
        require(self.observed_ids().count('late-topic-backlog') == 1,
                'late-topic acknowledged backlog replayed after persisted source identity was reopened')
        self.report['observations']['late-topic-final-native-offset'] = 2
        self.immutable_transition('combined-group-topic-change', 2, verify_delivery=False,
            Topics=[self.topic + '-other'],
            AmazonManagedKafkaEventSourceConfig={'ConsumerGroupId': self.group + '-other'})
        failure = next(row for row in self.report['observations']['combined-group-topic-change-rollback']['events']
                       if row['LogicalResourceId'] == 'Mapping' and row['ResourceStatus'] == 'UPDATE_FAILED')
        require(failure.get('PhysicalResourceId') == self.mapping,
                'combined mutable topic/group change attempted replacement instead of failing in-resource')
        self.replace_position_group_topic(2)

    def replace_position_group_topic(self, old_offset):
        self.update('position-replacement-disabled', Enabled=False)
        old_mapping, old_topic, old_group = self.mapping, self.topic, self.group
        self.topic, self.group = self.prefix + '-replacement', self.prefix + '-replacement-group'
        self.native('create')
        timestamp = int(time.time()) - 60
        self.produce('position-replacement-backlog')
        properties = copy.deepcopy(self.properties)
        properties.update(StartingPosition='AT_TIMESTAMP', StartingPositionTimestamp=timestamp,
            Topics=[self.topic], AmazonManagedKafkaEventSourceConfig={'ConsumerGroupId': self.group})
        self.cfn.update_stack(StackName=self.stack, TemplateBody=json.dumps(self.template(properties)))
        stack = self.wait(lambda: self.stack_ready('UPDATE_COMPLETE'), 'position/group/topic replacement', 240)
        self.properties = properties
        self.mapping, mapping, outputs = self.projection(stack)
        require(self.mapping != old_mapping, 'immutable position/group/topic replacement retained the old UUID')
        require(mapping['StartingPosition'] == 'AT_TIMESTAMP'
                and int(mapping['StartingPositionTimestamp'].timestamp()) == timestamp
                and mapping['Topics'] == [self.topic]
                and mapping['AmazonManagedKafkaEventSourceConfig']['ConsumerGroupId'] == self.group,
                'replacement mapping did not preserve the new source position/topic/group')
        self.wait(lambda: self.absent(self.functions, 'get_event_source_mapping', 'ResourceNotFoundException', UUID=old_mapping),
                  'replaced mapping deletion')
        self.wait(lambda: self.mapping_state('Disabled'), 'replacement disabled state')
        self.quiet_before_first_delivery('disabled replacement delivered its timestamp-selected backlog')
        self.update('position-replacement-enabled', Enabled=True)
        self.delivered('position-replacement-backlog', 0)
        self.checkpoint(1)
        self.delete_stack('late-topic', 1)
        old_offsets = self.protocol('offsets', Topic=old_topic, Group=old_group, **self.protocol_security)['offsets'][old_topic]
        require(next((row['CommittedOffset'] for row in old_offsets if row['Partition'] == 0), -1) == old_offset,
                'replacement or stack deletion erased the original external broker group checkpoint')
        self.report['observations']['position-group-topic-replacement'] = {
            'old_uuid': old_mapping, 'new_uuid': mapping['UUID'], 'mapping': mapping, 'outputs': outputs,
            'old_topic': old_topic, 'old_group': old_group, 'old_group_offsets': old_offsets,
            'new_group_committed_offset': 1, 'requested_starting_timestamp': timestamp}

    def stack_absent(self):
        try:
            self.cfn.describe_stacks(StackName=self.stack)
        except ClientError as error:
            require(error.response['Error']['Code'] == 'ValidationError'
                    and 'does not exist' in error.response['Error']['Message'], str(error))
            return True
        return False

    def delete_stack(self, label, offset=None):
        if not self.stack_absent():
            self.cfn.delete_stack(StackName=self.stack)
            self.wait(self.stack_absent, 'owned CFN stack deletion', 240)
        if self.mapping:
            self.wait(lambda: self.absent(self.functions, 'get_event_source_mapping', 'ResourceNotFoundException', UUID=self.mapping),
                      'stack-owned mapping deletion')
            self.report['cleanup'][label + '_stack_mapping'] = True
            self.mapping = None
        require(self.cluster() and self.function_ready(), 'stack deletion removed the external broker/function')
        self.report['cleanup'][label + '_external_resources_survived_stack_deletion'] = True
        if offset is not None:
            require(self.committed(offset), 'stack deletion erased the external broker consumer group checkpoint')
            self.produce(label + '-after-stack-deletion')
            self.quiet(offset, 'deleted stack mapping still consumed the external broker')
            retained = self.native('read', Partition=0, Offset=offset)
            require(json.loads(retained['value'])['id'] == label + '-after-stack-deletion',
                    'stack deletion lost actual external broker bytes')
            response = self.functions.invoke(FunctionName=self.function,
                Payload=json.dumps({'records': {}, 'after_stack_deletion': label}).encode())
            payload = json.loads(response['Payload'].read())
            require(response['StatusCode'] == 200 and not response.get('FunctionError') and payload == {'processed': 0},
                    'external function cannot execute after stack deletion')
            self.wait(lambda: self.take(lambda row: row['event'].get('after_stack_deletion') == label),
                      'external Lambda effect after stack deletion')
            self.report['observations'][label + '-stack-deletion'] = {
                'retained_offset': offset, 'broker_record': retained, 'external_function_result': payload}
        self.report['cleanup'][label + '_stack'] = True
        self.stack = None

    def cleanup(self):
        try:
            if self.stack:
                self.delete_stack('cleanup')
        finally:
            try:
                super().cleanup()
            finally:
                if self.secret:
                    self.secrets.delete_secret(SecretId=self.secret, ForceDeleteWithoutRecovery=True)
                    require(self.absent(self.secrets, 'describe_secret', 'ResourceNotFoundException', SecretId=self.secret),
                            'owned SCRAM secret remains')
                    self.report['cleanup']['scram_secret'] = True
                if self.key:
                    self.kms.schedule_key_deletion(KeyId=self.key, PendingWindowInDays=7)
                    self.report['cleanup']['local_key'] = 'PendingDeletion; no native AWS key created'

    def run(self):
        try:
            self.start()
            self.setup(create_topic=not self.args.late_topic_only)
            if self.args.late_topic_only:
                self.late_topic()
            else:
                if not self.args.default_position_only:
                    self.deploy('configured')
                    self.exercise()
                self.default_position()
                if not self.args.default_position_only:
                    self.late_topic()
        except BaseException as error:
            self.report['failure'] = repr(error)
            if self.controller.process is not None:
                self.capture_diagnostics()
            raise
        finally:
            try:
                if self.controller.process is None and self.arn:
                    self.start()
                if self.controller.process is not None:
                    self.cleanup()
            finally:
                self.controller.stop(timeout=60)
                self.report_path.write_text(json.dumps(self.report, default=str, indent=2) + '\n')
        print(json.dumps({'report': str(self.report_path), 'observations': list(self.report['observations']),
                          'cleanup': self.report['cleanup']}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', required=True)
    parser.add_argument('--protocol-probe', required=True)
    parser.add_argument('--state-directory', required=True)
    parser.add_argument('--docker-host', default='unix:///var/run/docker.sock')
    parser.add_argument('--telemetry-directory', required=True)
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument('--default-position-only', action='store_true',
                       help='run only the fresh-topic omitted-position proof and exact-owned cleanup')
    modes.add_argument('--late-topic-only', action='store_true',
                       help='deploy the disabled mapping before creating its topic, then deliver/restart/clean')
    CloudFormationMSKProof(parser.parse_args()).run()


if __name__ == '__main__':
    main()
