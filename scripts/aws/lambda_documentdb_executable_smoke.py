#!/usr/bin/env python3
"""Signed DocumentDB controls/native TLS Mongo changes -> real Lambda -> SQS.

Requires boto3, pymongo, a built integrated stackd and installed native images.
Uses explicit local credentials, never ambient AWS. Reports retained-token,
whole-batch retry, current authority, incarnation and exact-owned cleanup facts.
"""
import argparse
import datetime
import io
import json
import os
from pathlib import Path
import socket
import sqlite3
import subprocess
import time
import urllib.request
import uuid
import zipfile

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError
from pymongo import MongoClient


def require(value, message):
    if not value:
        raise AssertionError(message)


HANDLER = '''import json, os
import boto3

def invoke(event, context):
    failed = os.environ['FAIL'] == '1'
    observation = {'request_id': context.aws_request_id, 'event': event, 'failed': failed}
    boto3.client('sqs', endpoint_url=os.environ['PROOF_ENDPOINT']).send_message(QueueUrl=os.environ['QUEUE_URL'], MessageBody=json.dumps(observation))
    if failed:
        raise RuntimeError('owned DocumentDB whole-batch retry proof')
    return {'processed': len(event['events'])}
'''


class Proof:
    def __init__(self, args):
        self.args = args
        self.state = Path(args.state_directory).resolve()
        self.state.mkdir(parents=True, exist_ok=True)
        self.database = self.state / 'documentdb.sqlite'
        require(not self.database.exists(), 'fresh isolated state directory required')
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0))
            self.port = sock.getsockname()[1]
        self.endpoint = f'http://127.0.0.1:{self.port}'
        self.prefix = 'docdb-lambda-proof-' + uuid.uuid4().hex[:10]
        self.env = {k: v for k, v in os.environ.items() if not k.startswith('AWS_')}
        self.env['AWS_EC2_METADATA_DISABLED'] = 'true'
        self.process = self.log = self.mongo = None
        self.starts = 0
        self.cluster_arn = self.instance = self.mapping = self.function = self.role = self.queue = self.secret = self.kms_key = None
        self.runtime_ids = []
        self.extra_mappings = []
        self.policies = set()
        self.pending = []
        self.report = {'prefix': self.prefix, 'endpoint': self.endpoint, 'observations': {}, 'cleanup': {}, 'limitations': ['Native data plane is the DocumentDB owner\'s compatible MongoDB replica set, not AWS DocumentDB.', 'AWS VPC/SG/NACL attachments are unsupported by the owner; this proof uses verified loopback TLS.', 'Native AWS admission is captured separately; no AWS database fleet is created.']}
        self.docdb, self.functions, self.sqs, self.iam, self.secrets, self.kms, self.logs = [self.client(name) for name in ('docdb', 'lambda', 'sqs', 'iam', 'secretsmanager', 'kms', 'logs')]

    def client(self, service):
        return boto3.client(service, endpoint_url=self.endpoint, region_name='us-east-1', aws_access_key_id='test', aws_secret_access_key='test', config=Config(retries={'total_max_attempts': 1}, connect_timeout=5, read_timeout=120))

    def wait(self, fn, label, timeout=180):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            value = fn()
            if value:
                return value
            time.sleep(.2)
        raise TimeoutError(label)

    def start(self):
        self.starts += 1
        self.log = (self.state / f'controller-{self.starts}.log').open('wb')
        command = [str(Path(self.args.binary).resolve()), '-listen', f'0.0.0.0:{self.port}', '-public-endpoint', self.endpoint, '-database', str(self.database), '-docker-host', self.args.docker_host, '-lambda-runtime', '-docdb-runtime', '-lambda-telemetry-directory', self.args.telemetry_directory, '-compute-endpoint', f'http://host.docker.internal:{self.port}', *self.args.runtime_argument]
        self.process = subprocess.Popen(command, env=self.env, stdout=self.log, stderr=self.log)
        self.wait(self.health, 'controller readiness')

    def health(self):
        require(self.process.poll() is None, f'controller exited; inspect controller-{self.starts}.log')
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

    def cluster_ready(self):
        row = self.docdb.describe_db_clusters(DBClusterIdentifier=self.prefix)['DBClusters'][0]
        require(row['Status'] != 'failed', 'native cluster failed')
        return row if row['Status'] == 'available' else None

    def create_source(self, password):
        self.cluster_arn = self.docdb.create_db_cluster(DBClusterIdentifier=self.prefix, Engine='docdb', EngineVersion='5.0', MasterUsername='proofuser', MasterUserPassword=password)['DBCluster']['DBClusterArn']
        with sqlite3.connect(self.database) as db:
            runtime_id, = db.execute('SELECT runtime_id FROM docdb_cluster WHERE partition=? AND account_id=? AND region=? AND name=?', ('aws', '000000000000', 'us-east-1', self.prefix)).fetchone()
        require(runtime_id not in self.runtime_ids, 'source incarnation reused')
        self.runtime_ids.append(runtime_id)
        self.docdb.create_db_instance(DBInstanceIdentifier=self.prefix, DBClusterIdentifier=self.prefix, DBInstanceClass='db.r5.large', Engine='docdb')
        self.instance = self.prefix
        cluster = self.wait(self.cluster_ready, 'native DocumentDB writer', 240)
        with sqlite3.connect(self.database) as db:
            ca, replica = db.execute('SELECT ca,replica_set FROM docdb_cluster WHERE partition=? AND account_id=? AND region=? AND name=?', ('aws', '000000000000', 'us-east-1', self.prefix)).fetchone()
        trust = self.state / 'source-ca.pem'
        trust.write_bytes(ca)
        self.mongo = MongoClient(cluster['Endpoint'], cluster['Port'], username='proofuser', password=password, authSource='admin', tls=True, tlsCAFile=str(trust), replicaSet=replica, retryWrites=False, serverSelectionTimeoutMS=10000)
        require(self.mongo.admin.command('ping')['ok'] == 1, 'native authenticated TLS connection failed')
        return runtime_id

    def delete_source(self):
        if self.mongo:
            self.mongo.close()
            self.mongo = None
        if self.instance:
            self.docdb.delete_db_instance(DBInstanceIdentifier=self.instance)
            self.wait(lambda: self.absent(self.docdb, 'describe_db_instances', 'DBInstanceNotFound', DBInstanceIdentifier=self.instance), 'writer deletion')
            self.instance = None
        if self.cluster_arn:
            self.docdb.delete_db_cluster(DBClusterIdentifier=self.prefix, SkipFinalSnapshot=True)
            self.wait(lambda: self.absent(self.docdb, 'describe_db_clusters', 'DBClusterNotFoundFault', DBClusterIdentifier=self.prefix), 'cluster deletion')
            self.cluster_arn = None

    def checkpoint(self, mapping=None):
        with sqlite3.connect(self.database) as db:
            row = db.execute('SELECT incarnation,hex(resume_token),start_seconds,start_increment FROM lambda_documentdb_checkpoints WHERE uuid=?', (mapping or self.mapping,)).fetchone()
        return row

    def mapping_state(self, state='Enabled'):
        row = self.functions.get_event_source_mapping(UUID=self.mapping)
        return row if row['State'] == state else None

    def enable(self, enabled):
        self.functions.update_event_source_mapping(UUID=self.mapping, Enabled=enabled)
        self.wait(lambda: self.mapping_state('Enabled' if enabled else 'Disabled'), 'mapping lifecycle')

    def environment(self, fail):
        return {'Variables': {'FAIL': str(int(fail)), 'PROOF_ENDPOINT': f'http://host.docker.internal:{self.port}', 'QUEUE_URL': self.queue.replace('127.0.0.1', 'host.docker.internal')}}

    def function_ready(self):
        row = self.functions.get_function_configuration(FunctionName=self.function)
        return row if row['State'] == 'Active' and row.get('LastUpdateStatus', 'Successful') == 'Successful' else None

    def set_failure(self, failed):
        self.functions.update_function_configuration(FunctionName=self.function, Environment=self.environment(failed))
        self.wait(self.function_ready, 'function configuration')

    def receive(self):
        rows = self.sqs.receive_message(QueueUrl=self.queue, MaxNumberOfMessages=10, WaitTimeSeconds=1).get('Messages', [])
        for row in rows:
            self.sqs.delete_message(QueueUrl=self.queue, ReceiptHandle=row['ReceiptHandle'])
        return [json.loads(row['Body']) for row in rows]

    def take(self, predicate):
        self.pending.extend(self.receive())
        for i, row in enumerate(self.pending):
            if predicate(row):
                return self.pending.pop(i)
        return None

    def ids(self, observation):
        return [row['event'].get('documentKey', {}).get('_id') for row in observation['event']['events']]

    def policy(self, name, statements):
        self.iam.put_role_policy(RoleName=self.role, PolicyName=name, PolicyDocument=json.dumps({'Version': '2012-10-17', 'Statement': statements}))
        self.policies.add(name)

    def remove_policy(self, name):
        self.iam.delete_role_policy(RoleName=self.role, PolicyName=name)
        self.policies.discard(name)

    def denied_source(self, label, deny, restore):
        before = self.checkpoint()
        deny()
        self.mongo.eventsdb.events.insert_one({'_id': label})
        def rejection():
            result = self.functions.get_event_source_mapping(UUID=self.mapping).get('LastProcessingResult')
            return result if result not in ('OK', 'No records processed', None, '') else None
        status = self.wait(rejection, label + ' source rejection')
        require(self.checkpoint() == before and not self.receive(), label + ' advanced token or invoked runtime')
        restore()
        delivered = self.wait(lambda: self.take(lambda row: label in self.ids(row)), label + ' authority recovery')
        self.wait(lambda: self.checkpoint() != before, label + ' committed token')
        self.report['observations'][label] = {'blocked': status, 'committed_position_during_denial': before, 'recovered': delivered, 'committed_position_after_recovery': self.checkpoint()}

    def create_scope_mapping(self, database, collection, position, timestamp=None):
        settings = {'DatabaseName': database}
        if collection is not None:
            settings['CollectionName'] = collection
        request = {'FunctionName': self.function, 'EventSourceArn': self.cluster_arn, 'StartingPosition': position, 'BatchSize': 2, 'MaximumBatchingWindowInSeconds': 1, 'DocumentDBEventSourceConfig': settings, 'SourceAccessConfigurations': [{'Type': 'BASIC_AUTH', 'URI': self.secret}]}
        if timestamp is not None:
            request['StartingPositionTimestamp'] = datetime.datetime.fromtimestamp(timestamp, datetime.timezone.utc)
        mapping = self.functions.create_event_source_mapping(**request)['UUID']
        self.extra_mappings.append(mapping)
        self.wait(lambda: self.functions.get_event_source_mapping(UUID=mapping)['State'] == 'Enabled', 'additional native source scope')
        self.wait(lambda: self.checkpoint(mapping), 'additional source initial position')
        return mapping

    def delete_scope_mapping(self, mapping):
        self.functions.delete_event_source_mapping(UUID=mapping)
        self.wait(lambda: self.absent(self.functions, 'get_event_source_mapping', 'ResourceNotFoundException', UUID=mapping), 'additional source cleanup')
        self.extra_mappings.remove(mapping)

    def source_scopes(self):
        self.mongo.eventsdb.replaytrim.insert_many([{'_id': 'trim-one'}, {'_id': 'trim-two'}])
        mapping = self.create_scope_mapping('eventsdb', 'replaytrim', 'TRIM_HORIZON')
        trimmed = self.wait(lambda: self.take(lambda row: self.ids(row) == ['trim-one', 'trim-two']), 'native oplog trim-horizon replay')
        self.report['observations']['trim_horizon'] = trimmed
        self.delete_scope_mapping(mapping)
        self.mongo.eventsdb.replayat.insert_one({'_id': 'before-timestamp'})
        time.sleep(1.1)
        cutoff = int(time.time())
        self.mongo.eventsdb.replayat.insert_one({'_id': 'at-timestamp'})
        mapping = self.create_scope_mapping('eventsdb', 'replayat', 'AT_TIMESTAMP', cutoff)
        positioned = self.wait(lambda: self.take(lambda row: self.ids(row) == ['at-timestamp']), 'native operation timestamp replay')
        self.report['observations']['at_timestamp'] = {'starting_position': cutoff, 'delivered': positioned}
        self.delete_scope_mapping(mapping)
        self.mongo.wideproof.one.insert_one({'_id': 'wide-before-latest'})
        mapping = self.create_scope_mapping('wideproof', None, 'LATEST')
        self.mongo.wideproof.one.insert_one({'_id': 'wide-one'})
        self.mongo.wideproof.two.insert_one({'_id': 'wide-two'})
        wide = self.wait(lambda: self.take(lambda row: self.ids(row) == ['wide-one', 'wide-two']), 'database-wide native watch')
        require([item['event']['ns']['coll'] for item in wide['event']['events']] == ['one', 'two'], 'database-wide watch lost collection identity')
        self.report['observations']['database_wide_watch'] = wide
        self.delete_scope_mapping(mapping)

    def cleanup(self):
        for mapping in list(self.extra_mappings):
            self.delete_scope_mapping(mapping)
        if self.mapping:
            self.functions.delete_event_source_mapping(UUID=self.mapping)
            self.wait(lambda: self.absent(self.functions, 'get_event_source_mapping', 'ResourceNotFoundException', UUID=self.mapping), 'mapping cleanup')
            with sqlite3.connect(self.database) as db:
                require(db.execute('SELECT count(*) FROM lambda_documentdb_checkpoints WHERE uuid=?', (self.mapping,)).fetchone()[0] == 0, 'deleted mapping retained checkpoint')
            self.report['cleanup']['mapping_and_checkpoint'] = True
            self.mapping = None
        if self.function:
            self.functions.delete_function(FunctionName=self.function)
            require(self.absent(self.functions, 'get_function', 'ResourceNotFoundException', FunctionName=self.function), 'function remains')
            self.function = None
            self.report['cleanup']['function'] = True
        try:
            self.logs.delete_log_group(logGroupName='/aws/lambda/' + self.prefix)
        except ClientError as error:
            require(error.response['Error']['Code'] == 'ResourceNotFoundException', str(error))
        self.delete_source()
        self.report['cleanup']['source_controls'] = True
        for runtime_id in self.runtime_ids:
            for command in (['ps', '-aq'], ['volume', 'ls', '-q']):
                result = subprocess.run(['docker', '--host', self.args.docker_host, *command, '--filter', 'label=stackd.docdb.id=' + runtime_id], capture_output=True, text=True, check=True)
                require(not result.stdout.strip(), 'owned native DocumentDB resource remains: ' + result.stdout)
        self.report['cleanup']['native_containers_and_volumes'] = True
        if self.secret:
            self.secrets.delete_secret(SecretId=self.secret, ForceDeleteWithoutRecovery=True)
            self.report['cleanup']['secret'] = True
        if self.kms_key:
            self.kms.schedule_key_deletion(KeyId=self.kms_key, PendingWindowInDays=7)
            self.report['cleanup']['local_kms_key'] = 'PendingDeletion in isolated local state; no AWS key created'
        if self.role:
            for name in list(self.policies):
                self.remove_policy(name)
            self.iam.delete_role(RoleName=self.role)
            require(self.absent(self.iam, 'get_role', 'NoSuchEntity', RoleName=self.role), 'role remains')
            self.report['cleanup']['role'] = True
        if self.queue:
            self.sqs.delete_queue(QueueUrl=self.queue)
            self.report['cleanup']['queue'] = True

    def run(self):
        self.start()
        try:
            password = 'Proof-' + uuid.uuid4().hex
            original = self.create_source(password)
            self.queue = self.sqs.create_queue(QueueName=self.prefix)['QueueUrl']
            self.kms_key = self.kms.create_key()['KeyMetadata']['KeyId']
            self.secret = self.secrets.create_secret(Name=self.prefix, KmsKeyId=self.kms_key, SecretString=json.dumps({'username': 'proofuser', 'password': password}))['ARN']
            self.role = self.prefix
            role_arn = self.iam.create_role(RoleName=self.role, AssumeRolePolicyDocument=json.dumps({'Version': '2012-10-17', 'Statement': [{'Effect': 'Allow', 'Principal': {'Service': 'lambda.amazonaws.com'}, 'Action': 'sts:AssumeRole'}]}))['Role']['Arn']
            self.policy('source-target', [{'Effect': 'Allow', 'Resource': '*', 'Action': ['rds:DescribeDBClusters', 'secretsmanager:GetSecretValue', 'kms:Decrypt', 'sqs:SendMessage', 'logs:CreateLogGroup', 'logs:CreateLogStream', 'logs:PutLogEvents']}])
            package = io.BytesIO()
            with zipfile.ZipFile(package, 'w') as archive:
                archive.writestr('entry.py', HANDLER)
            self.function = self.prefix
            self.functions.create_function(FunctionName=self.function, Role=role_arn, Runtime='python3.12', Handler='entry.invoke', Code={'ZipFile': package.getvalue()}, Timeout=20, MemorySize=128, Environment=self.environment(False))
            self.wait(self.function_ready, 'real Lambda deployment')
            self.mongo.eventsdb.events.insert_one({'_id': 'before-latest'})
            self.mapping = self.functions.create_event_source_mapping(FunctionName=self.function, EventSourceArn=self.cluster_arn, StartingPosition='LATEST', BatchSize=2, MaximumBatchingWindowInSeconds=1, DocumentDBEventSourceConfig={'DatabaseName': 'eventsdb', 'CollectionName': 'events', 'FullDocument': 'UpdateLookup'}, SourceAccessConfigurations=[{'Type': 'BASIC_AUTH', 'URI': self.secret}])['UUID']
            self.wait(self.mapping_state, 'mapping enabled')
            self.wait(self.checkpoint, 'native initial position retained')
            self.mongo.eventsdb.unselected.insert_one({'_id': 'wrong-collection'})
            self.mongo.unselected.events.insert_one({'_id': 'wrong-database'})
            self.mongo.eventsdb.events.insert_many([{'_id': 'first', 'value': 1}, {'_id': 'second', 'value': 2}])
            delivered = self.wait(lambda: self.take(lambda row: self.ids(row) == ['first', 'second']), 'native changes -> real runtime -> SQS')
            require(delivered['event']['eventSource'] == 'aws:docdb' and delivered['event']['eventSourceArn'] == self.cluster_arn, 'DocumentDB envelope mismatch')
            require(all(row['event']['ns'] == {'db': 'eventsdb', 'coll': 'events'} and '$timestamp' in row['event']['clusterTime'] for row in delivered['event']['events']), 'native namespace/timestamp changed')
            self.wait(lambda: self.checkpoint()[1], 'successful resume token')
            committed = self.checkpoint()
            self.report['observations']['native_payload_and_selection'] = delivered
            self.set_failure(True)
            self.mongo.eventsdb.events.insert_many([{'_id': 'retry-one'}, {'_id': 'retry-two'}])
            failed = self.wait(lambda: self.take(lambda row: row['failed']), 'failed real runtime batch')
            repeated = self.wait(lambda: self.take(lambda row: row['failed'] and row['request_id'] != failed['request_id']), 'whole-batch retry')
            require(failed['event'] == repeated['event'] and self.ids(failed) == ['retry-one', 'retry-two'], 'retry changed batch')
            require(self.checkpoint() == committed, 'function failure advanced native resume token')
            self.report['observations']['whole_batch_retry'] = {'attempts': [failed, repeated], 'committed_position_before': committed, 'committed_position_after_failures': self.checkpoint()}
            self.enable(False)
            self.receive()
            self.pending.clear()
            self.stop()
            self.mongo.eventsdb.events.insert_one({'_id': 'while-controller-stopped'})
            self.start()
            self.wait(self.cluster_ready, 'retained source reopened')
            require(self.checkpoint() == committed, 'restart changed committed token')
            self.set_failure(False)
            self.enable(True)
            recovered = []
            def recovery():
                for row in self.receive():
                    if not row['failed']:
                        recovered.extend(self.ids(row))
                return len(recovered) >= 3
            self.wait(recovery, 'uncommitted native change-stream recovery')
            require(recovered == ['retry-one', 'retry-two', 'while-controller-stopped'], 'restart lost/reordered/redelivered committed events: ' + str(recovered))
            self.report['observations']['restart_committed_token'] = recovered
            self.wait(lambda: self.checkpoint() != committed, 'recovery token committed')
            self.denied_source('role-denial', lambda: self.policy('deny-source', [{'Effect': 'Deny', 'Action': 'rds:DescribeDBClusters', 'Resource': self.cluster_arn}]), lambda: self.remove_policy('deny-source'))
            self.denied_source('secret-denial', lambda: self.policy('deny-secret', [{'Effect': 'Deny', 'Action': 'secretsmanager:GetSecretValue', 'Resource': self.secret}]), lambda: self.remove_policy('deny-secret'))
            self.denied_source('kms-denial', lambda: self.kms.disable_key(KeyId=self.kms_key), lambda: self.kms.enable_key(KeyId=self.kms_key))
            for mode in ('Default', 'UpdateLookup'):
                self.functions.update_event_source_mapping(UUID=self.mapping, DocumentDBEventSourceConfig={'FullDocument': mode})
                self.wait(self.mapping_state, 'fullDocument update')
                before_update = self.checkpoint()
                self.mongo.eventsdb.events.update_one({'_id': 'first'}, {'$set': {'mode': mode}})
                update = self.wait(lambda: self.take(lambda row: any(item['event'].get('operationType') == 'update' and item['event'].get('updateDescription', {}).get('updatedFields', {}).get('mode') == mode for item in row['event']['events'])), 'native fullDocument ' + mode)
                native = update['event']['events'][0]['event']
                require(('fullDocument' in native) == (mode == 'UpdateLookup'), 'fullDocument option did not reach native watch')
                self.report['observations']['full_document_' + mode] = update
                self.wait(lambda: self.checkpoint() != before_update, 'fullDocument token committed')
            before_oversized = self.checkpoint()
            self.mongo.eventsdb.events.insert_many([{'_id': 'oversized', 'data': 'x' * (7 * 1024 * 1024)}, {'_id': 'after-oversized'}])
            after_oversized = self.wait(lambda: self.take(lambda row: self.ids(row) == ['after-oversized']), 'oversized native event drop preserves subsequent delivery')
            self.wait(lambda: self.checkpoint() != before_oversized, 'oversized native event progress')
            self.report['observations']['oversized_record_drop'] = after_oversized
            self.source_scopes()
            old_checkpoint = self.checkpoint()
            self.delete_source()
            replacement = self.create_source(password)
            require(replacement != original, 'replacement reused native source incarnation')
            self.mongo.eventsdb.events.insert_one({'_id': 'replacement-must-not-deliver'})
            diagnostic = self.wait(lambda: 'incarnation changed' in self.functions.get_event_source_mapping(UUID=self.mapping).get('LastProcessingResult', ''), 'replacement source guard')
            require(self.checkpoint() == old_checkpoint and not self.receive(), 'replacement source bypassed incarnation guard')
            self.report['observations']['source_incarnation_guard'] = diagnostic
        except Exception as error:
            self.report['failure'] = {'type': type(error).__name__, 'message': str(error)}
            if self.mapping and self.process is not None:
                try:
                    self.report['failure']['mapping'] = self.functions.get_event_source_mapping(UUID=self.mapping)
                    self.report['failure']['checkpoint'] = self.checkpoint()
                except Exception as diagnostic_error:
                    self.report['failure']['diagnostic_error'] = str(diagnostic_error)
            raise
        finally:
            try:
                if self.process is None and any((self.cluster_arn, self.function, self.role, self.secret, self.queue, self.kms_key)):
                    self.start()
                    if self.instance:
                        self.wait(lambda: self.docdb.describe_db_clusters(DBClusterIdentifier=self.prefix)['DBClusters'][0]['Status'] in ('available', 'failed', 'stopped'), 'native source cleanup readiness')
                if self.process:
                    self.cleanup()
            finally:
                self.stop()
                (self.state / 'report.json').write_text(json.dumps(self.report, default=str, indent=2) + '\n')
        print(json.dumps({'report': str(self.state / 'report.json'), 'observations': list(self.report['observations']), 'cleanup': self.report['cleanup']}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', required=True)
    parser.add_argument('--state-directory', required=True)
    parser.add_argument('--docker-host', default='unix:///var/run/docker.sock')
    parser.add_argument('--telemetry-directory', default='/home/r/dev/minor/stackd/bin')
    parser.add_argument('--runtime-argument', action='append', default=[], help='Additional integrated CLI runtime arguments; Lambda and DocumentDB are enabled by this workflow')
    Proof(parser.parse_args()).run()


if __name__ == '__main__':
    main()
