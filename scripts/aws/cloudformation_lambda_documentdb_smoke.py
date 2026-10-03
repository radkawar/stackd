#!/usr/bin/env python3
"""Signed CFN -> native TLS Mongo change stream -> official Python Lambda -> SQS.

Requires built stackd and cloudformation_lambda_documentdb_sdk helpers, installed
native images, boto3 and pymongo. Uses explicit local credentials/endpoints only.
Local Mongo-compatible delivery is not native AWS DocumentDB delivery evidence.
"""
import argparse
import copy
import io
import json
from pathlib import Path
import shlex
import sqlite3
import subprocess
import sys
import time
import uuid
import zipfile

from botocore.exceptions import ClientError
from pymongo import MongoClient
from lambda_documentdb_executable_smoke import HANDLER, Proof, require


class DeploymentProof(Proof):
    def __init__(self, args):
        super().__init__(args)
        self.cfn = self.client('cloudformation')
        self.stack = None
        self.properties = None
        self.effects = []
        self.report['command'] = shlex.join([sys.executable, *sys.argv])
        self.report['scope'] = 'Local executable integration, not native AWS lifecycle evidence'
        self.report['scenario'] = args.scenario

    def receive(self):
        rows = super().receive()
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
            raise AssertionError('CloudFormation ' + status + ': ' + json.dumps(
                self.cfn.describe_stack_events(StackName=self.stack)['StackEvents'], default=str))
        return None

    def projection(self, stack):
        outputs = {row['OutputKey']: row['OutputValue'] for row in stack['Outputs']}
        identifier = outputs['MappingUUID']
        require(str(uuid.UUID(identifier)) == identifier and outputs['MappingId'] == identifier,
                'CFN Ref/GetAtt Id is not the live UUID')
        row = self.functions.get_event_source_mapping(UUID=identifier)
        require(row['EventSourceArn'] == self.cluster_arn and
                row['EventSourceMappingArn'] == outputs['MappingArn'], 'CFN source/ARN projection mismatch')
        resource = self.cfn.describe_stack_resource(StackName=self.stack, LogicalResourceId='Mapping')['StackResourceDetail']
        require(resource['PhysicalResourceId'] == identifier, 'CFN physical ID differs from Lambda UUID')
        return identifier, row, outputs

    def create_source(self, password):
        if self.args.scenario != 'late-instance':
            return super().create_source(password)
        self.password = password
        self.cluster_arn = self.docdb.create_db_cluster(DBClusterIdentifier=self.prefix, Engine='docdb',
            EngineVersion='5.0', MasterUsername='proofuser', MasterUserPassword=password)['DBCluster']['DBClusterArn']
        with sqlite3.connect(self.database) as db:
            runtime_id, = db.execute('SELECT runtime_id FROM docdb_cluster WHERE partition=? AND account_id=? AND region=? AND name=?',
                ('aws', '000000000000', 'us-east-1', self.prefix)).fetchone()
        self.runtime_ids.append(runtime_id)
        return runtime_id

    def attach_writer(self):
        self.docdb.create_db_instance(DBInstanceIdentifier=self.prefix, DBClusterIdentifier=self.prefix,
                                     DBInstanceClass='db.r5.large', Engine='docdb')
        self.instance = self.prefix
        cluster = self.wait(self.cluster_ready, 'late native DocumentDB writer', 240)
        with sqlite3.connect(self.database) as db:
            ca, replica = db.execute('SELECT ca,replica_set FROM docdb_cluster WHERE partition=? AND account_id=? AND region=? AND name=?',
                ('aws', '000000000000', 'us-east-1', self.prefix)).fetchone()
        trust = self.state / 'source-ca.pem'
        trust.write_bytes(ca)
        self.mongo = MongoClient(cluster['Endpoint'], cluster['Port'], username='proofuser', password=self.password,
            authSource='admin', tls=True, tlsCAFile=str(trust), replicaSet=replica, retryWrites=False,
            serverSelectionTimeoutMS=10000)
        require(self.mongo.admin.command('ping')['ok'] == 1, 'late writer authenticated TLS connection failed')

    def setup(self):
        password = 'Proof-' + uuid.uuid4().hex
        self.create_source(password)
        self.queue = self.sqs.create_queue(QueueName=self.prefix)['QueueUrl']
        self.kms_key = self.kms.create_key()['KeyMetadata']['KeyId']
        self.secret = self.secrets.create_secret(Name=self.prefix, KmsKeyId=self.kms_key,
            SecretString=json.dumps({'username': 'proofuser', 'password': password}))['ARN']
        self.role = self.prefix
        role = self.iam.create_role(RoleName=self.role, AssumeRolePolicyDocument=json.dumps({
            'Version': '2012-10-17', 'Statement': [{'Effect': 'Allow', 'Principal': {'Service': 'lambda.amazonaws.com'},
                                                'Action': 'sts:AssumeRole'}]}))['Role']['Arn']
        self.policy('source-target', [{'Effect': 'Allow', 'Resource': '*', 'Action': [
            'rds:DescribeDBClusters', 'secretsmanager:GetSecretValue', 'kms:Decrypt',
            'sqs:SendMessage', 'logs:CreateLogGroup', 'logs:CreateLogStream', 'logs:PutLogEvents']}])
        handler = HANDLER.replace("'request_id': context.aws_request_id,", "'request_id': context.aws_request_id, 'function_version': context.function_version, 'invoked_function_arn': context.invoked_function_arn,")
        package = io.BytesIO()
        with zipfile.ZipFile(package, 'w') as archive:
            archive.writestr('entry.py', handler)
        self.function = self.prefix
        self.functions.create_function(FunctionName=self.function, Role=role, Runtime='python3.12',
            Handler='entry.invoke', Code={'ZipFile': package.getvalue()}, Timeout=20, MemorySize=128,
            Environment=self.environment(False))
        self.wait(self.function_ready, 'external official Python Lambda')
        self.version = self.functions.publish_version(FunctionName=self.function)['Version']
        self.alias = self.functions.create_alias(FunctionName=self.function, Name='live', FunctionVersion=self.version)['AliasArn']
        if self.mongo is not None:
            self.mongo.eventsdb.events.insert_one({'_id': 'preexisting', 'value': 1})
        self.report['observations']['independent_resources_before_stack'] = {
            'source': self.docdb.describe_db_clusters(DBClusterIdentifier=self.prefix)['DBClusters'][0],
            'function': self.functions.get_function_configuration(FunctionName=self.function),
            'document': self.mongo.eventsdb.events.find_one({'_id': 'preexisting'}) if self.mongo is not None else None}

    def deploy(self):
        self.properties = {'FunctionName': self.alias, 'EventSourceArn': self.cluster_arn,
            'StartingPosition': 'TRIM_HORIZON', 'Enabled': False, 'BatchSize': 1,
            'MaximumBatchingWindowInSeconds': 1,
            'DocumentDBEventSourceConfig': {'DatabaseName': 'eventsdb', 'CollectionName': 'events', 'FullDocument': 'Default'},
            'SourceAccessConfigurations': [{'Type': 'BASIC_AUTH', 'URI': self.secret}]}
        if self.args.scenario == 'defaults':
            for name in ('StartingPosition', 'BatchSize', 'MaximumBatchingWindowInSeconds'):
                self.properties.pop(name)
            self.properties['DocumentDBEventSourceConfig'] = {'DatabaseName': 'eventsdb'}
        self.stack = self.prefix + '-stack'
        template = self.state / 'go-sdk-template.json'
        template.write_text(json.dumps(self.template(self.properties)))
        result = subprocess.run([str(Path(self.args.sdk_helper).resolve()), '-endpoint', self.endpoint,
            '-stack', self.stack, '-template', str(template)], capture_output=True, text=True, timeout=200)
        self.report['observations']['go_sdk_create_read_and_error'] = {
            'exit_status': result.returncode, 'stdout': result.stdout, 'stderr': result.stderr}
        require(result.returncode == 0, 'signed Go SDK deployment failed: ' + result.stderr)
        decoded = json.loads(result.stdout)
        self.report['observations']['go_sdk_create_read_and_error']['decoded'] = decoded
        self.mapping, mapping, outputs = self.projection(self.wait(lambda: self.stack_ready('CREATE_COMPLETE'), 'CFN creation'))
        require(decoded['outputs'] == outputs, 'Go and Python SDK output projections differ')
        self.wait(lambda: self.mapping_state('Disabled'), 'initial disabled mapping')
        self.report['observations']['deployment'] = mapping

    def update(self, label, remove=(), **changes):
        properties = copy.deepcopy(self.properties)
        properties.update(changes)
        for key in remove:
            properties.pop(key, None)
        old = self.mapping
        self.cfn.update_stack(StackName=self.stack, TemplateBody=json.dumps(self.template(properties)))
        stack = self.wait(lambda: self.stack_ready('UPDATE_COMPLETE'), 'CFN ' + label, 180)
        identifier, mapping, outputs = self.projection(stack)
        require(identifier == old, label + ': mutable update replaced the mapping')
        self.mapping = identifier
        self.properties = properties
        self.wait(lambda: self.mapping_state('Enabled' if properties.get('Enabled', True) else 'Disabled'), label)
        self.report['observations'][label] = {'mapping': mapping, 'outputs': outputs, 'previous_uuid': old}
        return mapping

    def quiet(self, label, checkpoint=None):
        time.sleep(3)
        require(not self.receive() and not self.pending, label + ': unexpected runtime effect')
        if checkpoint is not None:
            require(self.checkpoint() == checkpoint, label + ': checkpoint changed')

    def delivered(self, identifier, database='eventsdb', collection='events'):
        before = self.checkpoint()
        row = self.wait(lambda: self.take(lambda item: identifier in self.ids(item)), 'real Lambda effect: ' + identifier, 90)
        event = row['event']
        require(event['eventSource'] == 'aws:docdb' and event['eventSourceArn'] == self.cluster_arn,
                'DocumentDB envelope mismatch')
        matching = next(item['event'] for item in event['events'] if item['event'].get('documentKey', {}).get('_id') == identifier)
        require(matching['ns'] == {'db': database, 'coll': collection} and '$timestamp' in matching['clusterTime'],
                'native namespace/operation time missing')
        require(row['request_id'] and not row['failed'], 'real runtime invocation failed')
        if before is None or not before[1]:
            self.wait(lambda: self.checkpoint() and self.checkpoint()[1], 'committed native token')
        self.report['observations'][identifier] = row
        return row

    def insert(self, identifier, database='eventsdb', collection='events'):
        before = self.checkpoint()
        self.mongo[database][collection].insert_one({'_id': identifier, 'value': 1})
        row = self.delivered(identifier, database, collection)
        self.wait(lambda: self.checkpoint() != before, identifier + ' token commit')
        return row

    def core(self):
        self.mongo.eventsdb.events.insert_one({'_id': 'disabled-backlog'})
        self.quiet('disabled initial stack')
        self.update('enable-stack', Enabled=True)
        first = self.delivered('preexisting')
        self.delivered('disabled-backlog')
        require(first['function_version'] == self.version and first['invoked_function_arn'] == self.alias,
                'qualified alias target was not invoked')
        self.wait(lambda: self.checkpoint() and self.checkpoint()[1], 'backlog native checkpoint')
        for mode in ('Default', 'UpdateLookup'):
            if mode != 'Default':
                self.update('full-document-mode-' + mode, DocumentDBEventSourceConfig={
                    'DatabaseName': 'eventsdb', 'CollectionName': 'events', 'FullDocument': mode})
            before = self.checkpoint()
            self.mongo.eventsdb.events.update_one({'_id': 'preexisting'}, {'$set': {'mode': mode}})
            row = self.wait(lambda: self.take(lambda item: any(record['event'].get('operationType') == 'update'
                and record['event'].get('updateDescription', {}).get('updatedFields', {}).get('mode') == mode
                for record in item['event']['events'])), 'native fullDocument ' + mode, 90)
            native = next(record['event'] for record in row['event']['events'] if record['event'].get('operationType') == 'update')
            require(('fullDocument' in native) == (mode == 'UpdateLookup'), 'native fullDocument watch option mismatch')
            if mode == 'UpdateLookup':
                require(native['fullDocument']['mode'] == mode, 'lookup returned stale source bytes')
            self.wait(lambda: self.checkpoint() != before, 'update token commit')
            self.report['observations']['full_document_' + mode] = row
        self.update('disable-before-restart', Enabled=False)
        committed = self.checkpoint()
        self.mongo.eventsdb.events.insert_one({'_id': 'disabled-before-restart'})
        self.quiet('disabled backlog checkpoint', committed)
        self.stop()
        self.mongo.eventsdb.events.insert_one({'_id': 'controller-stopped'})
        self.start()
        self.wait(self.cluster_ready, 'retained native source after SQLite reopen', 180)
        stack = self.wait(lambda: self.stack_ready('UPDATE_COMPLETE'), 'durable stack reopen')
        require(self.projection(stack)[0] == self.mapping and self.checkpoint() == committed,
                'restart changed stack identity or committed native token')
        require(self.mongo.eventsdb.events.find_one({'_id': 'controller-stopped'}) is not None,
                'restart lost source data')
        self.report['observations']['restart_checkpoint'] = {'before': committed, 'after_reopen': self.checkpoint(),
            'mapping_uuid': self.mapping, 'native_document': self.mongo.eventsdb.events.find_one({'_id': 'controller-stopped'})}
        self.update('enable-after-restart', Enabled=True)
        self.delivered('disabled-before-restart')
        self.delivered('controller-stopped')
        self.wait(lambda: self.checkpoint() != committed, 'restart backlog commit')
        self.denied_source('current-role-denial', lambda: self.policy('deny-source', [
            {'Effect': 'Deny', 'Action': 'rds:DescribeDBClusters', 'Resource': self.cluster_arn}]),
            lambda: self.remove_policy('deny-source'))
        self.denied_source('current-secret-denial', lambda: self.policy('deny-secret', [
            {'Effect': 'Deny', 'Action': 'secretsmanager:GetSecretValue', 'Resource': self.secret}]),
            lambda: self.remove_policy('deny-secret'))
        self.update('qualified-version-target', FunctionName=self.function + ':' + self.version)
        version_effect = self.insert('qualified-version')
        require(version_effect['function_version'] == self.version and version_effect['invoked_function_arn'].endswith(':' + self.version),
                'qualified version target was not invoked')
        observed = [identifier for row in self.effects for identifier in self.ids(row)]
        require(observed.count('disabled-before-restart') == 1 and observed.count('controller-stopped') == 1
                and observed.count('disabled-backlog') == 1,
                'restart replayed committed backlog')

    def retained_lookup(self, label):
        before = self.checkpoint()
        self.mongo.eventsdb.events.update_one({'_id': 'preexisting'}, {'$set': {'removal': label}})
        row = self.wait(lambda: self.take(lambda item: any(record['event'].get('operationType') == 'update'
            and record['event'].get('updateDescription', {}).get('updatedFields', {}).get('removal') == label
            for record in item['event']['events'])), 'retained native UpdateLookup after ' + label, 90)
        native = next(record['event'] for record in row['event']['events']
                      if record['event'].get('updateDescription', {}).get('updatedFields', {}).get('removal') == label)
        require(native.get('fullDocument', {}).get('removal') == label,
                'removal changed the native fullDocument lookup option')
        self.wait(lambda: self.checkpoint() != before, label + ' update token commit')
        self.report['observations'][label + '-native-update'] = row

    def settings(self):
        self.update('enable-settings', Enabled=True)
        self.delivered('preexisting')
        self.insert('settings-initial-checkpoint')
        for name, config, rejected_db, rejected_collection in (
            ('collection', {'DatabaseName': 'eventsdb', 'CollectionName': 'changed', 'FullDocument': 'UpdateLookup'},
             'eventsdb', 'changed'),
            ('database', {'DatabaseName': 'changeddb', 'CollectionName': 'changed', 'FullDocument': 'UpdateLookup'},
             'changeddb', 'changed')):
            row = self.update(name + '-edit-retains-native-namespace', DocumentDBEventSourceConfig=config)
            require(row['DocumentDBEventSourceConfig'] == {
                'DatabaseName': 'eventsdb', 'CollectionName': 'events', 'FullDocument': 'UpdateLookup'},
                'CFN namespace edit differs from measured native no-op')
            self.mongo[rejected_db][rejected_collection].insert_one({'_id': name + '-new-namespace-excluded'})
            self.insert(name + '-original-namespace-delivered')
            self.quiet(name + ' edit must retain creation namespace')
        for label, config in (
            ('remove-collection-field', {'DatabaseName': 'eventsdb', 'FullDocument': 'UpdateLookup'}),
            ('remove-database-field', {'CollectionName': 'events', 'FullDocument': 'UpdateLookup'}),
            ('remove-full-document-field', {'DatabaseName': 'eventsdb', 'CollectionName': 'events'})):
            row = self.update(label, DocumentDBEventSourceConfig=config)
            require(row['DocumentDBEventSourceConfig'] == {
                'DatabaseName': 'eventsdb', 'CollectionName': 'events', 'FullDocument': 'UpdateLookup'},
                label + ' differs from measured native retention')
        self.retained_lookup('remove-full-document-field')
        row = self.update('explicit-batch-window', BatchSize=17, MaximumBatchingWindowInSeconds=2)
        require(row['BatchSize'] == 17 and row['MaximumBatchingWindowInSeconds'] == 2,
                'explicit batch/window did not update')
        row = self.update('remove-batch-window', remove=('BatchSize', 'MaximumBatchingWindowInSeconds'))
        require(row['BatchSize'] == 100 and row['MaximumBatchingWindowInSeconds'] == 2,
                'batch/window removal differs from measured reset/retention')
        self.insert('after-batch-window-removal')
        row = self.update('remove-documentdb-config', remove=('DocumentDBEventSourceConfig',))
        require(row['DocumentDBEventSourceConfig'] == {
            'DatabaseName': 'eventsdb', 'CollectionName': 'events', 'FullDocument': 'UpdateLookup'},
            'whole DocumentDB config removal did not retain native config')
        self.insert('after-config-removal')
        self.retained_lookup('remove-documentdb-config')
        row = self.update('remove-source-credentials', remove=('SourceAccessConfigurations',))
        require(row['SourceAccessConfigurations'] == [{'Type': 'BASIC_AUTH', 'URI': self.secret}],
                'credential removal differs from measured native retention')
        self.insert('after-credential-removal')

    def late_instance(self):
        require(self.instance is None and self.mongo is None and self.checkpoint() is None,
                'disabled CFN admission unexpectedly required or opened a source writer')
        self.report['observations']['disabled_mapping_without_writer'] = {
            'mapping': self.functions.get_event_source_mapping(UUID=self.mapping),
            'instances': self.docdb.describe_db_instances()['DBInstances'],
            'source_incarnation': self.runtime_ids[0]}
        self.attach_writer()
        self.mongo.eventsdb.events.insert_one({'_id': 'preexisting', 'value': 1})
        self.quiet('late writer remains disabled until CFN update')
        self.update('enable-late-writer', Enabled=True)
        self.delivered('preexisting')
        self.insert('late-writer-real-delivery')
        self.update('disable-late-writer-for-restart', Enabled=False)
        committed = self.checkpoint()
        self.stop()
        self.mongo.eventsdb.events.insert_one({'_id': 'late-writer-controller-stopped'})
        self.start()
        self.wait(self.cluster_ready, 'late writer source reopened', 180)
        require(self.checkpoint() == committed, 'late writer restart lost native checkpoint')
        require(self.projection(self.wait(lambda: self.stack_ready('UPDATE_COMPLETE'), 'late writer stack reopen'))[0] == self.mapping,
                'late writer restart lost CFN mapping identity')
        self.report['observations']['late_writer_restart_checkpoint'] = {'before': committed, 'after': self.checkpoint()}
        self.update('enable-late-writer-after-restart', Enabled=True)
        self.delivered('late-writer-controller-stopped')
        self.wait(lambda: self.checkpoint() != committed, 'late writer resumed backlog commit')
        committed = self.checkpoint()
        original = self.runtime_ids[0]
        self.delete_source()
        replacement = super().create_source(self.password)
        require(replacement != original, 'recreated cluster reused source incarnation')
        self.mongo.eventsdb.events.insert_many([{'_id': 'preexisting'}, {'_id': 'new-incarnation-must-not-deliver'}])
        def incarnation_rejection():
            result = self.functions.get_event_source_mapping(UUID=self.mapping).get('LastProcessingResult', '')
            return result if 'incarnation changed' in result else None
        status = self.wait(incarnation_rejection, 'retained mapping source-incarnation fence', 90)
        self.quiet('new incarnation must not advance old mapping', committed)
        self.report['observations']['source_incarnation_fence'] = {
            'original': original, 'replacement': replacement, 'result': status, 'retained_checkpoint': self.checkpoint(),
            'native_document': self.mongo.eventsdb.events.find_one({'_id': 'new-incarnation-must-not-deliver'})}

    def defaults(self):
        row = self.functions.get_event_source_mapping(UUID=self.mapping)
        require(row['StartingPosition'] == 'LATEST' and row['BatchSize'] == 100
                and row['DocumentDBEventSourceConfig'] == {'DatabaseName': 'eventsdb', 'FullDocument': 'Default'},
                'omitted-property creation differs from native disabled CFN admission')
        require('MaximumBatchingWindowInSeconds' not in row,
                'native 500ms default must omit the integral batching-window projection')
        self.mongo.eventsdb.other.insert_one({'_id': 'before-latest-enable'})
        self.quiet('default-position disabled mapping')
        self.update('enable-default-position', Enabled=True)
        self.wait(self.checkpoint, 'default LATEST initial native position')
        self.insert('database-wide-first')
        self.insert('database-wide-other', collection='other')
        self.quiet('default LATEST excludes earlier source bytes')
        observed = [identifier for effect in self.effects for identifier in self.ids(effect)]
        require(observed == ['database-wide-first', 'database-wide-other'],
                'default LATEST replayed preexisting bytes or omitted collection narrowed database watch')

    def replacement(self):
        self.update('enable-before-replacement', Enabled=True)
        self.delivered('preexisting')
        self.insert('committed-before-replacement')
        self.update('disable-before-replacement', Enabled=False)
        committed = self.checkpoint()
        properties = copy.deepcopy(self.properties)
        properties['StartingPosition'] = 'LATEST'
        self.cfn.update_stack(StackName=self.stack, TemplateBody=json.dumps(self.template(properties)))
        stack = self.wait(lambda: self.stack_ready('UPDATE_ROLLBACK_COMPLETE'), 'same-target replacement rollback', 180)
        identifier, row, outputs = self.projection(stack)
        require(identifier == self.mapping and self.checkpoint() == committed,
                'failed replacement changed surviving mapping or native token')
        events = self.cfn.describe_stack_events(StackName=self.stack)['StackEvents']
        require(any('ResourceConflictException' in event.get('ResourceStatusReason', '') for event in events),
                'replacement rollback did not report the same-target mapping conflict')
        self.report['observations']['starting-position-replacement-rollback'] = {
            'mapping': row, 'outputs': outputs, 'events': events, 'retained_checkpoint': committed}
        self.update('enable-after-replacement-rollback', Enabled=True)
        self.insert('surviving-mapping-after-replacement-rollback')
        properties = copy.deepcopy(self.properties)
        properties['DocumentDBEventSourceConfig']['FullDocument'] = 'Invalid'
        self.cfn.update_stack(StackName=self.stack, TemplateBody=json.dumps(self.template(properties)))
        stack = self.wait(lambda: self.stack_ready('UPDATE_ROLLBACK_COMPLETE'), 'invalid setting rollback', 180)
        require(self.projection(stack)[0] == self.mapping, 'rollback changed live identity')
        self.report['observations']['invalid-setting-rollback'] = self.cfn.describe_stack_events(StackName=self.stack)['StackEvents']
        self.insert('after-rollback')

    def delete_stack(self, prove=False):
        if not self.stack:
            return
        mapping = self.mapping
        self.cfn.delete_stack(StackName=self.stack)
        def gone():
            try:
                return self.cfn.describe_stacks(StackName=self.stack)['Stacks'][0]['StackStatus'] == 'DELETE_COMPLETE'
            except ClientError as error:
                require(error.response['Error']['Code'] == 'ValidationError', str(error))
                return True
        self.wait(gone, 'owned CFN deletion', 180)
        if mapping:
            require(self.absent(self.functions, 'get_event_source_mapping', 'ResourceNotFoundException', UUID=mapping),
                    'stack deletion left mapping')
            require(self.checkpoint(mapping) is None, 'stack deletion left native checkpoint')
        self.mapping = None
        self.stack = None
        self.report['cleanup']['stack_mapping_and_checkpoint'] = True
        if prove:
            require(self.cluster_ready() and self.function_ready(), 'stack deleted independent source or function')
            require(self.mongo.eventsdb.events.find_one({'_id': 'preexisting'}) is not None, 'stack deleted source data')
            # Set a fresh observation boundary after deletion, before new source
            # bytes. Earlier at-least-once attempts remain retained in effects.
            self.receive()
            self.pending.clear()
            self.mongo.eventsdb.events.insert_one({'_id': 'after-stack-deletion'})
            self.quiet('deleted stack must not invoke')
            invoked = self.functions.invoke(FunctionName=self.alias, Payload=b'{"events": []}')
            result = json.loads(invoked['Payload'].read())
            require(not invoked.get('FunctionError') and result == {'processed': 0}, 'external function no longer invokes')
            self.wait(lambda: self.take(lambda row: row['event'] == {'events': []}), 'independent function after stack deletion')
            self.report['observations']['external_resources_survive_deletion'] = {
                'document': self.mongo.eventsdb.events.find_one({'_id': 'after-stack-deletion'}),
                'source': self.docdb.describe_db_clusters(DBClusterIdentifier=self.prefix)['DBClusters'][0],
                'function_result': result}

    def run(self):
        try:
            self.start()
            self.setup()
            self.deploy()
            getattr(self, self.args.scenario.replace('-', '_'))()
            self.delete_stack(prove=True)
        except Exception as error:
            self.report['failure'] = {'type': type(error).__name__, 'message': str(error)}
            if self.mapping and self.process is not None:
                try:
                    self.report['failure']['mapping'] = self.functions.get_event_source_mapping(UUID=self.mapping)
                    self.report['failure']['checkpoint'] = self.checkpoint()
                except Exception as diagnostic:
                    self.report['failure']['diagnostic_error'] = str(diagnostic)
            raise
        finally:
            try:
                if self.process is None and self.cluster_arn:
                    self.start()
                    self.wait(self.cluster_ready, 'cleanup native readiness', 180)
                if self.process:
                    self.delete_stack()
                    self.cleanup()
            except Exception as error:
                self.report['cleanup_failure'] = {'type': type(error).__name__, 'message': str(error)}
                raise
            finally:
                try:
                    self.stop()
                finally:
                    self.report['runtime_effects'] = self.effects
                    report = Path(self.args.report)
                    report.parent.mkdir(parents=True, exist_ok=True)
                    report.write_text(json.dumps(self.report, default=str, indent=2) + '\n')
        print(json.dumps({'report': self.args.report, 'observations': list(self.report['observations']), 'cleanup': self.report['cleanup']}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', required=True)
    parser.add_argument('--sdk-helper', required=True)
    parser.add_argument('--state-directory', required=True)
    parser.add_argument('--report', required=True)
    parser.add_argument('--docker-host', default='unix:///var/run/docker.sock')
    parser.add_argument('--telemetry-directory', default=str(Path(__file__).resolve().parents[2] / 'bin'))
    parser.add_argument('--runtime-argument', action='append', default=[])
    parser.add_argument('--scenario', choices=['core', 'replacement', 'defaults', 'settings', 'late-instance'], default='core')
    DeploymentProof(parser.parse_args()).run()


if __name__ == '__main__':
    main()
