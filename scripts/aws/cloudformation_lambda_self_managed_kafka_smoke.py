#!/usr/bin/env python3
"""Signed CFN -> self-managed TLS/SCRAM Kafka -> official Python Lambda -> SQS.

Uses only the explicitly started local stackd endpoint. Requires built stackd,
msk_protocol_probe, Lambda telemetry binaries, Docker, and the existing proof's
preloaded Kafka/Python Lambda images. The state directory must be fresh. Runtime
setup, Kafka protocol operations, executable restart, and owned native cleanup
are shared with lambda_self_managed_kafka_smoke.SelfManagedProof.
"""
import argparse
import base64
import copy
import json
import time
import uuid

from botocore.exceptions import ClientError

from lambda_self_managed_kafka_smoke import SelfManagedProof
from msk_executable_smoke import require


class CloudFormationKafkaProof(SelfManagedProof):
    def __init__(self, args):
        super().__init__(args)
        self.cfn = self.client('cloudformation')
        self.stack = None
        self.properties = None
        self.effects = []
        self.report_path = self.state / 'cloudformation-lambda-self-managed-kafka-report.json'

    def receive(self):
        rows = super().receive()
        if rows:
            self.effects.extend(rows)
        return rows

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
        require('EventSourceArn' not in mapping, 'self-managed CFN mapping acquired a cluster ARN')
        require(mapping['SelfManagedEventSource']['Endpoints']['KAFKA_BOOTSTRAP_SERVERS'] == sorted(
            self.properties['SelfManagedEventSource']['Endpoints']['KafkaBootstrapServers']),
            'CFN KafkaBootstrapServers did not translate to Lambda bootstrap endpoints')
        resource = self.cfn.describe_stack_resource(StackName=self.stack, LogicalResourceId='Mapping')['StackResourceDetail']
        require(resource['PhysicalResourceId'] == identifier, 'stack resource and Lambda mapping identity differ')
        tags = self.functions.list_tags(Resource=outputs['MappingArn']).get('Tags', {})
        require(tags.get('proof') == self.prefix, 'stack-owned mapping tag was not applied')
        return identifier, mapping, outputs

    def deploy(self):
        self.bootstrap_servers = self.msk.get_bootstrap_brokers(ClusterArn=self.arn)['BootstrapBrokerStringSaslScram'].split(',')
        require(len(self.bootstrap_servers) == 2, 'source replacement proof requires two actual brokers')
        self.properties = {'FunctionName': self.function, 'Enabled': False, 'Topics': [self.prefix],
            'StartingPosition': 'TRIM_HORIZON', 'BatchSize': 1,
            'SelfManagedEventSource': {'Endpoints': {'KafkaBootstrapServers': self.bootstrap_servers[:1]}},
            'SelfManagedKafkaEventSourceConfig': {'ConsumerGroupId': self.group},
            'SourceAccessConfigurations': [{'Type': 'SASL_SCRAM_512_AUTH', 'URI': self.secret},
                                           {'Type': 'SERVER_ROOT_CA_CERTIFICATE', 'URI': self.ca_secret}],
            'Tags': [{'Key': 'proof', 'Value': self.prefix}]}
        # Remember the exact owned name even if creation fails after admission.
        self.stack = self.prefix + '-mapping'
        self.cfn.create_stack(StackName=self.stack, TemplateBody=json.dumps(self.template(self.properties)))
        stack = self.wait(lambda: self.stack_ready('CREATE_COMPLETE'), 'CFN mapping creation', 240)
        self.mapping, mapping, outputs = self.projection(stack)
        require('MaximumBatchingWindowInSeconds' not in mapping,
                'Kafka default 500ms batching window was incorrectly projected as integer seconds')
        self.wait(lambda: self.mapping_state('Disabled'), 'initial disabled mapping')
        self.report['observations']['creation'] = {'mapping': mapping, 'outputs': outputs}

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
        self.wait(lambda: self.mapping_state('Enabled' if properties['Enabled'] else 'Disabled'), label)
        self.report['observations'][label] = {'mapping': mapping, 'outputs': outputs}
        return mapping

    def produce(self, identifier, **fields):
        self.native('produce', Partition=0, Values=[json.dumps({'id': identifier, **fields})])

    def delivered(self, identifier, offset, failed=False):
        row = self.wait(lambda: self.take(lambda value: value['fail'] == failed and any(
            json.loads(base64.b64decode(record['value'])).get('id') == identifier
            for records in value['event']['records'].values() for record in records)),
            'Python runtime effect for ' + identifier, 180)
        event = row['event']
        require(event['eventSource'] == 'SelfManagedKafka' and 'eventSourceArn' not in event,
                'incorrect self-managed Kafka event envelope')
        record = next(record for records in event['records'].values() for record in records
                      if json.loads(base64.b64decode(record['value'])).get('id') == identifier)
        require(record['topic'] == self.prefix and record['partition'] == 0 and record['offset'] == offset,
                'broker offset/topic/partition did not reach the Python runtime')
        require(row['request_id'], 'official Lambda runtime did not provide request identity')
        self.report['observations'][identifier] = row
        return row

    def checkpoint(self, offset):
        self.wait(lambda: self.committed(offset), 'native broker checkpoint ' + str(offset))

    def quiet(self, offset, label):
        time.sleep(3)
        require((offset is None or self.committed(offset)) and self.receive() is None, label)

    def restart(self):
        self.controller.stop(timeout=60)
        self.start()
        self.wait(self.cluster, 'real broker recovery after executable SQLite reopen', 240)
        stack = self.wait(lambda: self.stack_ready('UPDATE_COMPLETE'), 'durable stack recovery')
        require(self.projection(stack)[0] == self.mapping, 'stack/mapping identity changed after SQLite reopen')

    def filtered_ids(self):
        return [json.loads(base64.b64decode(record['value']))['id']
                for row in self.effects for records in row['event']['records'].values() for record in records]

    def replace_source(self, offset):
        self.update('source-replacement-disabled', Enabled=False)
        old_mapping = self.mapping
        properties = copy.deepcopy(self.properties)
        properties['SelfManagedEventSource'] = {'Endpoints': {'KafkaBootstrapServers': self.bootstrap_servers[1:]}}
        properties.pop('StartingPosition')
        self.cfn.update_stack(StackName=self.stack, TemplateBody=json.dumps(self.template(properties)))
        stack = self.wait(lambda: self.stack_ready('UPDATE_COMPLETE'), 'real bootstrap endpoint replacement', 240)
        self.properties = properties
        self.mapping, mapping, outputs = self.projection(stack)
        require(self.mapping != old_mapping, 'CFN source replacement retained the old mapping UUID')
        require(mapping['StartingPosition'] == 'TRIM_HORIZON', 'Kafka creation without StartingPosition did not use the native default')
        self.wait(lambda: self.absent(self.functions, 'get_event_source_mapping', 'ResourceNotFoundException', UUID=old_mapping),
                  'replaced mapping deletion')
        self.wait(lambda: self.mapping_state('Disabled'), 'replacement preserves disabled state')
        self.quiet(offset, 'source replacement erased or replayed the borrowed Kafka group checkpoint')
        self.update('source-replacement-enabled', Enabled=True)
        self.produce('source-replacement')
        self.delivered('source-replacement', offset)
        self.checkpoint(offset + 1)
        self.report['observations']['source-replacement-identity'] = {
            'old_uuid': old_mapping, 'new_uuid': self.mapping, 'mapping': mapping, 'outputs': outputs,
            'retained_native_offset': offset}
        return offset + 1

    def group_change_plan(self, offset):
        properties = copy.deepcopy(self.properties)
        properties['SelfManagedKafkaEventSourceConfig'] = {'ConsumerGroupId': self.group + '-planned'}
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
                    'group change-set public plan differs from native nonreplacement projection')
            target = next(row['Target'] for row in resource['Details']
                          if row['Target'].get('Name') == 'SelfManagedKafkaEventSourceConfig')
            require(target['RequiresRecreation'] == 'Never', 'group change-set target recreation differs from native plan')
            mapping = self.functions.get_event_source_mapping(UUID=self.mapping)
            require(mapping['SelfManagedKafkaEventSourceConfig']['ConsumerGroupId'] == self.group
                    and self.committed(offset), 'unexecuted change set altered live mapping or checkpoint')
            self.report['observations']['group-change-set'] = {'executed': False, 'description': plan}
        finally:
            self.cfn.delete_change_set(ChangeSetName=change)
            self.wait(lambda: self.absent(self.cfn, 'describe_change_set', 'ChangeSetNotFound', ChangeSetName=change),
                      'owned unexecuted change-set deletion')
            self.report['cleanup']['group_change_set'] = True

    def immutable_transition(self, label, offset, remove=(), **changes):
        # Native topic changes are rejected. Group changes attempt replacement,
        # but conflict with the live function/bootstrap/topic mapping. Both
        # roll back without changing the original UUID, group, or topic.
        properties = copy.deepcopy(self.properties)
        properties.update(changes)
        for name in remove:
            properties.pop(name, None)
        self.cfn.update_stack(StackName=self.stack, TemplateBody=json.dumps(self.template(properties)))
        stack = self.wait(lambda: self.stack_ready('UPDATE_ROLLBACK_COMPLETE'), label + ' rollback', 240)
        identifier, mapping, outputs = self.projection(stack)
        require(identifier == self.mapping
                and mapping['SelfManagedKafkaEventSourceConfig']['ConsumerGroupId'] == self.group
                and mapping['Topics'] == [self.prefix], 'failed CFN transition changed the original mapping/group/topic')
        require(self.committed(offset), 'failed CFN transition changed the broker checkpoint')
        self.produce(label)
        self.delivered(label, offset)
        self.checkpoint(offset + 1)
        self.report['observations'][label + '-rollback'] = {
            'stack_status': stack['StackStatus'], 'mapping': mapping, 'outputs': outputs,
            'events': self.cfn.describe_stack_events(StackName=self.stack)['StackEvents']}
        return offset + 1

    def exercise(self):
        self.produce('disabled-backlog')
        # Admission does not join/materialize the broker group. The first
        # enabled delivery below must still contain the record at offset zero.
        self.quiet(None, 'disabled CFN mapping delivered backlog')
        self.update('enabled', Enabled=True)
        self.delivered('disabled-backlog', 0)
        self.checkpoint(1)

        self.update('filter-added', Enabled=False, BatchSize=2, MaximumBatchingWindowInSeconds=1,
                    FilterCriteria={'Filters': [{'Pattern': '{"value":{"kind":["keep"]}}'}]})
        self.produce('filtered-out', kind='drop')
        self.produce('filter-match', kind='keep')
        self.quiet(1, 'disabled filtered mapping consumed backlog')
        self.update('filter-enabled', Enabled=True)
        self.delivered('filter-match', 2)
        self.checkpoint(3)
        require('filtered-out' not in self.filtered_ids(), 'filter delivered a rejected Kafka record')
        access = self.properties['SourceAccessConfigurations']
        removed = self.update('settings-removed', remove=(
            'FilterCriteria', 'BatchSize', 'MaximumBatchingWindowInSeconds', 'SourceAccessConfigurations'))
        require(removed['BatchSize'] == 100 and removed['MaximumBatchingWindowInSeconds'] == 1,
                'CFN omission did not reset batch size while retaining the Kafka batching window')
        require(sorted((row['Type'], row['URI']) for row in removed['SourceAccessConfigurations']) ==
                sorted((row['Type'], row['URI']) for row in access), 'CFN omission discarded current source access')
        reintroduced = [{**row, 'Type': 'SASL_SCRAM_256_AUTH'} if row['Type'] == 'SASL_SCRAM_512_AUTH'
                        else dict(row) for row in access]
        ignored = self.update('source-access-reintroduced', SourceAccessConfigurations=reintroduced)
        require(sorted((row['Type'], row['URI']) for row in ignored['SourceAccessConfigurations']) ==
                sorted((row['Type'], row['URI']) for row in access), 'CFN source-access reintroduction changed retained authentication')
        self.produce('filter-removal', kind='drop')
        self.delivered('filter-removal', 3)
        self.checkpoint(4)
        self.update('runtime-controls-restored', BatchSize=1, MaximumBatchingWindowInSeconds=0,
                    SourceAccessConfigurations=access)

        self.iam.put_role_policy(RoleName=self.role, PolicyName='deny-ca', PolicyDocument=json.dumps({
            'Version': '2012-10-17', 'Statement': [{'Effect': 'Deny',
            'Action': 'secretsmanager:GetSecretValue', 'Resource': self.ca_secret}]}))
        try:
            self.produce('iam-recovery')
            self.quiet(4, 'current IAM secret denial consumed a record')
        finally:
            self.iam.delete_role_policy(RoleName=self.role, PolicyName='deny-ca')
        self.delivered('iam-recovery', 4)
        self.checkpoint(5)

        current_ca = self.secrets.get_secret_value(SecretId=self.ca_secret)['SecretString']
        self.secrets.put_secret_value(SecretId=self.ca_secret, SecretString='{"certificate":"not a certificate"}')
        try:
            self.produce('current-secret-recovery')
            self.quiet(5, 'mapping reused stale CA secret instead of current AWSCURRENT')
        finally:
            self.secrets.put_secret_value(SecretId=self.ca_secret, SecretString=current_ca)
        self.delivered('current-secret-recovery', 5)
        self.checkpoint(6)

        self.kms.disable_key(KeyId=self.key)
        try:
            self.produce('kms-recovery')
            self.quiet(6, 'mapping consumed while the secret KMS key was disabled')
        finally:
            self.kms.enable_key(KeyId=self.key)
        self.delivered('kms-recovery', 6)
        self.checkpoint(7)

        self.produce('restart-retry', fail=True)
        self.delivered('restart-retry', 7, failed=True)
        require(self.committed(7), 'failed official Python invocation acknowledged its Kafka offset')
        self.update('retry-disabled', Enabled=False)
        self.restart()
        require(self.mapping_state('Disabled') and self.committed(7), 'disabled/uncommitted state lost after SQLite reopen')
        while self.receive():
            pass
        self.functions.update_function_configuration(FunctionName=self.function, Environment=self.environment('0'))
        self.wait(self.function_ready, 'runtime recovery configuration')
        version = self.functions.publish_version(FunctionName=self.function)['Version']
        # The qualified target must retain its snapshot, not invoke $LATEST.
        self.functions.update_function_configuration(FunctionName=self.function, Environment=self.environment('1'))
        self.wait(self.function_ready, 'latest configuration diverges from published version')
        self.update('version-target', FunctionName=self.function + ':' + version, Enabled=True)
        self.delivered('restart-retry', 7)
        self.checkpoint(8)
        self.functions.create_alias(FunctionName=self.function, Name='live', FunctionVersion=version)
        self.update('alias-target', FunctionName=self.function + ':live')
        self.produce('alias-delivery', fail=True)
        self.delivered('alias-delivery', 8)
        self.checkpoint(9)
        while self.receive():
            pass
        self.restart()
        self.quiet(9, 'acknowledged records replayed after executable restart')
        self.produce('post-restart')
        self.delivered('post-restart', 9)
        self.checkpoint(10)
        offset = self.replace_source(10)
        self.group_change_plan(offset)
        offset = self.immutable_transition('group-change', offset,
            SelfManagedKafkaEventSourceConfig={'ConsumerGroupId': self.group + '-changed'})
        offset = self.immutable_transition('group-removal', offset, remove=('SelfManagedKafkaEventSourceConfig',))
        offset = self.immutable_transition('topic-change', offset, Topics=[self.prefix + '-other'])
        offset = self.immutable_transition('topic-removal', offset, remove=('Topics',))
        offset = self.immutable_transition('on-demand-metrics', offset, MetricsConfig={'Metrics': ['EventCount']})
        self.report['observations']['final_native_offset'] = offset
        self.report['observations']['source_control_authority'] = 'function role explicitly denies kafka:*'

    def stack_absent(self):
        try:
            self.cfn.describe_stacks(StackName=self.stack)
        except ClientError as error:
            require(error.response['Error']['Code'] == 'ValidationError'
                    and 'does not exist' in error.response['Error']['Message'], str(error))
            return True
        return False

    def cleanup(self):
        if self.stack:
            if not self.stack_absent():
                self.cfn.delete_stack(StackName=self.stack)
                self.wait(self.stack_absent, 'owned CFN stack deletion', 240)
            if self.mapping:
                require(self.absent(self.functions, 'get_event_source_mapping', 'ResourceNotFoundException', UUID=self.mapping),
                        'CFN stack deletion left its mapping alive')
                self.report['cleanup']['stack_mapping'] = True
                self.mapping = None
            if self.arn and self.function:
                require(self.cluster() and self.function_ready(), 'stack deletion removed external broker/function')
                self.report['cleanup']['external_resources_survived_stack_deletion'] = True
            self.report['cleanup']['stack'] = True
            self.stack = None
        super().cleanup()

    def run(self):
        try:
            self.start()
            self.setup(brokers=2)
            self.deploy()
            self.exercise()
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
        print(json.dumps({'report': str(self.report_path), 'cleanup': self.report['cleanup']}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', required=True)
    parser.add_argument('--protocol-probe', required=True)
    parser.add_argument('--state-directory', required=True)
    parser.add_argument('--docker-host', default='unix:///var/run/docker.sock')
    parser.add_argument('--telemetry-directory', required=True)
    CloudFormationKafkaProof(parser.parse_args()).run()


if __name__ == '__main__':
    main()
