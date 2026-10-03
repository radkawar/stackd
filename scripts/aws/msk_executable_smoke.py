#!/usr/bin/env python3
"""Owned signed MSK/Pipes executable proof with a real Kafka protocol client.

Requires a built stackd and built msk_protocol_probe.go; uses no ambient AWS
credentials, no implicit pulls, and no native AWS fleet. Keeps an evidence report.
"""
import argparse
import base64
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
from botocore.exceptions import ClientError

from stackd_process import StackdProcess


def require(value, message):
    if not value:
        raise AssertionError(message)


class Proof:
    listen_host = '127.0.0.1'

    def __init__(self, args):
        self.args = args
        self.state = Path(args.state_directory).resolve()
        self.state.mkdir(parents=True, exist_ok=True)
        require(not (self.state / 'msk.sqlite').exists(), 'fresh state directory required')
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0))
            self.port = sock.getsockname()[1]
        self.endpoint = f'http://127.0.0.1:{self.port}'
        self.env = {k: v for k, v in os.environ.items() if not k.startswith('AWS_')}
        self.env['AWS_EC2_METADATA_DISABLED'] = 'true'
        self.prefix = 'msk-proof-' + uuid.uuid4().hex[:10]
        self.controller = StackdProcess(self.state)
        self.arn = self.config_arn = self.pipe = self.queue = self.role = None
        self.report = {'endpoint': self.endpoint, 'prefix': self.prefix, 'observations': {}, 'controllers': self.controller.runs, 'cleanup': {}}
        self.msk, self.pipes, self.sqs, self.iam = [self.client(name) for name in ('kafka', 'pipes', 'sqs', 'iam')]

    def client(self, service, key='test', region='us-east-1'):
        return boto3.client(service, endpoint_url=self.endpoint, region_name=region, aws_access_key_id=key,
                            aws_secret_access_key='test', config=Config(retries={'total_max_attempts': 1}, connect_timeout=5, read_timeout=90))

    def start(self):
        command = [str(Path(self.args.binary).resolve()), '-listen', f'{self.listen_host}:{self.port}',
            '-public-endpoint', self.endpoint,
            '-database', str(self.state / 'msk.sqlite'), '-docker-host', self.args.docker_host, '-msk-runtime',
            '-lambda-telemetry-directory', self.args.telemetry_directory,
            '-compute-endpoint', f'http://host.docker.internal:{self.port}']
        self.controller.start(command, self.endpoint, environment=self.env, timeout=180)

    def wait(self, fn, label, timeout=120):
        until = time.monotonic() + timeout
        while time.monotonic() < until:
            value = fn()
            if value:
                return value
            time.sleep(.2)
        raise TimeoutError(label)

    def cluster(self, arn=None):
        row = self.msk.describe_cluster(ClusterArn=arn or self.arn)['ClusterInfo']
        require(row['State'] != 'FAILED', 'native cluster failed: ' + json.dumps(row, default=str))
        return row if row['State'] == 'ACTIVE' else None

    def protocol(self, action, **kwargs):
        request = {'Endpoint': self.endpoint, 'ARN': self.arn, 'Action': action, 'Topic': self.prefix, **kwargs}
        result = subprocess.run([str(Path(self.args.protocol_probe).resolve())], input=json.dumps(request), text=True,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=self.env, timeout=55)
        require(result.returncode == 0, f'protocol {action} failed: {result.stderr}')
        return json.loads(result.stdout)

    def offsets(self, group):
        return self.protocol('offsets', Group=group)['offsets'][self.prefix]

    def receive(self):
        rows = self.sqs.receive_message(QueueUrl=self.queue, MaxNumberOfMessages=10, WaitTimeSeconds=1).get('Messages', [])
        if rows:
            for row in rows:
                self.sqs.delete_message(QueueUrl=self.queue, ReceiptHandle=row['ReceiptHandle'])
            return [json.loads(row['Body']) for row in rows]
        return None

    def absent(self, client, action, code, **params):
        try:
            getattr(client, action)(**params)
            return False
        except ClientError as error:
            require(error.response['Error']['Code'] == code, str(error))
            return True

    def denied(self, client, action, **params):
        try:
            getattr(client, action)(**params)
        except ClientError as error:
            require(error.response['ResponseMetadata']['HTTPStatusCode'] == 403, str(error))
            return error.response['Error']['Code']
        raise AssertionError('unauthorized control succeeded: ' + action)

    def run(self):
        self.start()
        try:
            config = self.msk.create_configuration(Name=self.prefix, KafkaVersions=['3.7.1'],
                ServerProperties=b'auto.create.topics.enable=false\nnum.partitions=3\nlog.retention.ms=86400000\n')
            self.config_arn = config['Arn']
            created = self.msk.create_cluster(ClusterName=self.prefix, KafkaVersion='3.7.1', NumberOfBrokerNodes=2,
                BrokerNodeGroupInfo={'InstanceType': 'kafka.local', 'ClientSubnets': []},
                ClientAuthentication={'Unauthenticated': {'Enabled': True}},
                EncryptionInfo={'EncryptionInTransit': {'ClientBroker': 'PLAINTEXT', 'InCluster': True}},
                ConfigurationInfo={'Arn': self.config_arn, 'Revision': 1})
            self.arn = created['ClusterArn']
            row = self.wait(self.cluster, 'native cluster readiness', 240)
            self.report['observations']['cluster'] = row
            self.protocol('create')
            metadata = self.protocol('metadata')
            self.report['observations']['native_metadata'] = metadata
            require(len(metadata['metadata']['Brokers']) == 2, 'MSK broker count is not native metadata count')
            self.protocol('produce', Partition=0, Values=['{"kind":"drop","id":0}'])
            self.protocol('produce', Partition=1, Values=['{"kind":"keep","id":1}'])
            self.protocol('produce', Partition=2, Values=['{"kind":"keep","id":2}'])
            read = self.protocol('read', Partition=1, Offset=0)
            require(json.loads(read['value'])['id'] == 1 and read['offset'] == 0, 'native partition/offset bytes differ')
            self.report['observations']['native_partition'] = read
            group = self.protocol('group', Group=self.prefix + '-independent')
            self.report['observations']['independent_consumer_group'] = group
            foreign = self.client('kafka', key='222222222222')
            self.report['observations']['cross_account_denial'] = self.denied(foreign, 'describe_cluster', ClusterArn=self.arn)
            self.msk.put_cluster_policy(ClusterArn=self.arn, Policy=json.dumps({'Version':'2012-10-17','Statement':[
                {'Effect':'Allow','Principal':{'AWS':'arn:aws:iam::222222222222:root'},'Action':['kafka:DescribeCluster','kafka:GetBootstrapBrokers'],'Resource':self.arn}]}))
            shared = foreign.get_bootstrap_brokers(ClusterArn=self.arn)['BootstrapBrokerString']
            require(shared == self.msk.get_bootstrap_brokers(ClusterArn=self.arn)['BootstrapBrokerString'], 'resource policy did not authorize owned endpoint')
            self.msk.delete_cluster_policy(ClusterArn=self.arn)
            self.report['observations']['current_resource_policy_revocation'] = self.denied(foreign, 'get_bootstrap_brokers', ClusterArn=self.arn)
            self.role = self.prefix
            self.pipe = self.prefix
            self.queue = self.sqs.create_queue(QueueName=self.prefix)['QueueUrl']
            target = self.sqs.get_queue_attributes(QueueUrl=self.queue, AttributeNames=['QueueArn'])['Attributes']['QueueArn']
            role = self.iam.create_role(RoleName=self.role, AssumeRolePolicyDocument=json.dumps({'Version': '2012-10-17', 'Statement': [
                {'Effect':'Allow','Principal':{'Service':'pipes.amazonaws.com'},'Action':'sts:AssumeRole'}]}))['Role']['Arn']
            self.iam.put_role_policy(RoleName=self.role, PolicyName='source-target', PolicyDocument=json.dumps({'Version':'2012-10-17','Statement':[
                {'Effect':'Allow','Action':['kafka:DescribeCluster','kafka:DescribeClusterV2','kafka:GetBootstrapBrokers','sqs:SendMessage'],'Resource':'*'}]}))
            self.pipes.create_pipe(Name=self.pipe, RoleArn=role, Source=self.arn, Target=target,
                SourceParameters={'ManagedStreamingKafkaParameters': {'TopicName':self.prefix, 'StartingPosition':'TRIM_HORIZON', 'BatchSize':1, 'ConsumerGroupID':self.prefix+'-pipe'},
                                  'FilterCriteria':{'Filters':[{'Pattern':json.dumps({'value':{'kind':['keep']}})}]}},
                TargetParameters={'InputTemplate':'{"id": <$.value.id>}'})
            received = []
            self.wait(lambda: self.collect(received, 2), 'filtered transformed Kafka delivery')
            require(sorted(received,key=lambda v:v['id']) == [{'id':1},{'id':2}], 'Kafka filter/transformation mismatch: '+str(received))
            self.wait(lambda: self.offsets_committed(self.prefix+'-pipe', {0:1,1:1,2:1}), 'native successful/filter commits')
            self.report['observations']['filtered_transformed_delivery'] = received
            self.iam.put_role_policy(RoleName=self.role, PolicyName='deny-target', PolicyDocument=json.dumps({'Version':'2012-10-17','Statement':[
                {'Effect':'Deny','Action':'sqs:SendMessage','Resource':target}]}))
            self.protocol('produce', Partition=2, Values=['{"kind":"keep","id":3}'])
            time.sleep(3)
            before = self.offsets(self.prefix+'-pipe')
            require(next(v['CommittedOffset'] for v in before if v['Partition'] == 2) == 1, 'failed effect was acknowledged')
            self.report['observations']['failed_effect_offsets'] = before
            self.controller.stop(timeout=60)
            self.start()
            self.wait(self.cluster, 'metadata restore reopens retained native bytes')
            durable = self.protocol('read', Partition=2, Offset=1)
            require(json.loads(durable['value'])['id'] == 3, 'controller restart lost native bytes')
            self.iam.delete_role_policy(RoleName=self.role, PolicyName='deny-target')
            recovery = self.wait(self.receive, 'target recovery from retained checkpoint')
            require(recovery == [{'id':3}], 'recovery lost/duplicated acknowledged earlier records: '+str(recovery))
            self.wait(lambda: self.offsets_committed(self.prefix+'-pipe',{0:1,1:1,2:2}), 'native recovered commit')
            self.report['observations']['restart_checkpoint_recovery'] = recovery
            row = self.wait(self.cluster, 'active before reboot')
            nodes = self.msk.list_nodes(ClusterArn=self.arn)['NodeInfoList']
            broker_id = str(int(nodes[0]['BrokerNodeInfo']['BrokerId']))
            self.msk.reboot_broker(ClusterArn=self.arn, BrokerIds=[broker_id])
            self.wait(self.cluster, 'native broker reboot', 240)
            retained = self.protocol('read', Partition=1, Offset=0)
            require(json.loads(retained['value'])['id'] == 1, 'native restart lost committed bytes')
            self.report['observations']['native_reboot_retains_bytes'] = retained
            revision = self.msk.update_configuration(Arn=self.config_arn, ServerProperties=b'auto.create.topics.enable=true\nnum.partitions=5\nlog.retention.ms=86400000\n')['LatestRevision']['Revision']
            current = self.wait(self.cluster, 'active before config update')
            self.msk.update_cluster_configuration(ClusterArn=self.arn, CurrentVersion=current['CurrentVersion'], ConfigurationInfo={'Arn':self.config_arn,'Revision':revision})
            updated = self.wait(self.cluster, 'effective configuration update', 240)
            require(updated['CurrentBrokerSoftwareInfo']['ConfigurationRevision'] == revision, 'configuration revision not effective')
            self.report['observations']['effective_revision'] = revision
            effective = self.protocol('config')['configs']
            require(len(effective) == 2 and all(v['num.partitions'] == '5' and v['auto.create.topics.enable'] == 'true' for v in effective.values()), 'native broker configuration did not change: ' + str(effective))
            self.report['observations']['native_effective_configuration'] = effective
            self.scram()
            self.iam.put_role_policy(RoleName=self.role, PolicyName='deny-source', PolicyDocument=json.dumps({'Version':'2012-10-17','Statement':[
                {'Effect':'Deny','Action':'kafka:*','Resource':self.arn}]}))
            self.pipes.stop_pipe(Name=self.pipe)
            self.wait(lambda: self.pipes.describe_pipe(Name=self.pipe)['CurrentState'] == 'STOPPED', 'idle stop without source authority')
            self.report['observations']['idle_stop_after_source_deny'] = 'STOPPED'
            self.iam.delete_role_policy(RoleName=self.role, PolicyName='deny-source')
            self.pipes.delete_pipe(Name=self.pipe)
            self.wait(lambda: self.absent(self.pipes,'describe_pipe','NotFoundException',Name=self.pipe), 'borrowed-group pipe deletion')
            require(all(row['CommittedOffset'] >= 1 for row in self.offsets(self.prefix+'-pipe')), 'deleting pipe erased borrowed group')
            self.pipe = self.prefix + '-owned'
            self.pipes.create_pipe(Name=self.pipe, RoleArn=role, Source=self.arn, Target=target, DesiredState='STOPPED',
                SourceParameters={'ManagedStreamingKafkaParameters': {'TopicName':self.prefix, 'StartingPosition':'TRIM_HORIZON', 'BatchSize':1}})
            self.msk.delete_cluster(ClusterArn=self.arn)
            self.wait(lambda: self.absent(self.msk,'describe_cluster','NotFoundException',ClusterArn=self.arn), 'source removal before pipe', 240)
            self.assert_native_absent(self.arn)
            self.arn = None
            self.pipes.delete_pipe(Name=self.pipe)
            self.wait(lambda: self.absent(self.pipes,'describe_pipe','NotFoundException',Name=self.pipe), 'owned-group cleanup after source absence')
            self.pipe = None
            self.report['observations']['delete_after_source_absent'] = 'ABSENT'
        finally:
            if self.controller.process is None:
                self.start()
            self.cleanup()
            self.controller.stop(timeout=60)
            (self.state / 'report.json').write_text(json.dumps(self.report,default=str,indent=2)+'\n')
        print(json.dumps({'report':str(self.state/'report.json'),'observations':list(self.report['observations']),'cleanup':self.report['cleanup']}))

    def scram(self):
        secrets, kms = self.client('secretsmanager'), self.client('kms')
        cluster = secret = key = None
        password = uuid.uuid4().hex
        try:
            cluster = self.msk.create_cluster(ClusterName=self.prefix + '-auth', KafkaVersion='3.7.1', NumberOfBrokerNodes=1,
                BrokerNodeGroupInfo={'InstanceType':'kafka.local','ClientSubnets':[]},
                ClientAuthentication={'Sasl':{'Scram':{'Enabled':True}}},
                EncryptionInfo={'EncryptionInTransit':{'ClientBroker':'TLS','InCluster':True}})['ClusterArn']
            self.wait(lambda: self.cluster(cluster), 'authenticated broker readiness', 240)
            key = kms.create_key(Policy=json.dumps({'Version':'2012-10-17','Statement':[
                {'Sid':'Owner','Effect':'Allow','Principal':{'AWS':'arn:aws:iam::000000000000:root'},'Action':'kms:*','Resource':'*'},
                {'Sid':'MSKDecrypt','Effect':'Allow','Principal':{'Service':'kafka.amazonaws.com'},'Action':'kms:Decrypt','Resource':'*',
                 'Condition':{'ArnEquals':{'aws:SourceArn':cluster}}}]}))['KeyMetadata']['KeyId']
            secret = secrets.create_secret(Name='AmazonMSK_' + self.prefix, KmsKeyId=key,
                SecretString=json.dumps({'username':'proof-user','password':password}))['ARN']
            kept = {'Sid':'KeepUnrelated','Effect':'Allow','Principal':{'AWS':'arn:aws:iam::000000000000:root'},
                    'Action':'secretsmanager:DescribeSecret','Resource':secret}
            secrets.put_resource_policy(SecretId=secret,ResourcePolicy=json.dumps({'Version':'2012-10-17','Statement':[kept]}))
            associated = self.msk.batch_associate_scram_secret(ClusterArn=cluster,SecretArnList=[secret])
            require(not associated.get('UnprocessedScramSecrets'),'SCRAM association rejected: '+str(associated))
            self.wait(lambda: self.cluster(cluster),'native SCRAM credential installation',240)
            with sqlite3.connect(self.state/'msk.sqlite') as db:
                # Public trust material only. No native bytes or credentials are
                # read from metadata to substitute for Kafka protocol effects.
                ca = db.execute('SELECT capem FROM msk_clusters WHERE arn=?',(cluster,)).fetchone()[0]
            settings = {'ARN':cluster,'CAPEM':base64.b64encode(ca).decode(),'Username':'proof-user','Password':password}
            self.protocol('create',**settings)
            self.protocol('produce',Partition=0,Values=['{"authenticated":true}'],**settings)
            actual = self.protocol('read',Partition=0,Offset=0,**settings)
            require(json.loads(actual['value']) == {'authenticated':True},'authenticated native bytes differ')
            denial = self.protocol_denied({**settings,'Password':'incorrect'})
            self.report['observations']['scram_native_denial'] = denial
            disassociated = self.msk.batch_disassociate_scram_secret(ClusterArn=cluster,SecretArnList=[secret])
            require(not disassociated.get('UnprocessedScramSecrets'),'SCRAM disassociation rejected')
            self.wait(lambda: self.cluster(cluster),'native credential revocation',240)
            self.report['observations']['scram_revoked_denial'] = self.protocol_denied(settings)
            policy = json.loads(secrets.get_resource_policy(SecretId=secret)['ResourcePolicy'])
            require(policy['Statement'] == [kept], 'association cleanup changed unrelated secret grants')
            self.report['observations']['scram_secret_policy_preserved'] = True
        finally:
            if cluster:
                self.msk.delete_cluster(ClusterArn=cluster)
                self.wait(lambda:self.absent(self.msk,'describe_cluster','NotFoundException',ClusterArn=cluster),'authenticated cluster deletion',240)
                self.assert_native_absent(cluster,'authenticated_')
            if secret:
                secrets.delete_secret(SecretId=secret,ForceDeleteWithoutRecovery=True)
                self.report['cleanup']['scram_secret'] = True
            if key:
                kms.schedule_key_deletion(KeyId=key,PendingWindowInDays=7)
                self.report['cleanup']['local_scram_key'] = 'PendingDeletion (AWS minimum 7-day window; no native AWS key created)'

    def protocol_denied(self, settings):
        request = {'Endpoint':self.endpoint,'Action':'metadata','Topic':self.prefix,**settings}
        out = subprocess.run([str(Path(self.args.protocol_probe).resolve())],input=json.dumps(request),text=True,
                             stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=self.env,timeout=55)
        require(out.returncode != 0 and ('SASL' in out.stderr or 'authentication' in out.stderr.lower()),'native authentication was not denied: '+out.stderr)
        return {'exit_status':out.returncode,'error':out.stderr.strip()}

    def assert_native_absent(self, arn, prefix=''):
        for kind in ('container','volume','network'):
            command = ['docker','--host',self.args.docker_host,kind,'ls','--filter','label=stackd.msk.arn='+arn,'--format','{{.ID}}']
            if kind == 'container':
                command.insert(5,'-a')
            result = subprocess.check_output(command,text=True)
            require(not result.strip(),'owned native resources remain: '+result)
            self.report['cleanup'][prefix+kind] = True

    def collect(self, received, count):
        rows = self.receive()
        if rows:
            received.extend(rows)
        return len(received) >= count

    def offsets_committed(self, group, expected):
        rows = self.offsets(group)
        return all(next((v['CommittedOffset'] for v in rows if v['Partition'] == p), -1) == o for p,o in expected.items())

    def cleanup(self):
        if self.pipe:
            try:
                self.pipes.delete_pipe(Name=self.pipe)
                self.wait(lambda: self.absent(self.pipes,'describe_pipe','NotFoundException',Name=self.pipe),'pipe deletion')
                self.report['cleanup']['pipe'] = True
            except ClientError as error:
                if error.response['Error']['Code'] != 'NotFoundException':
                    raise
        if self.arn:
            self.msk.delete_cluster(ClusterArn=self.arn)
            self.wait(lambda: self.absent(self.msk,'describe_cluster','NotFoundException',ClusterArn=self.arn),'native cluster deletion',240)
            self.report['cleanup']['cluster'] = True
            self.assert_native_absent(self.arn)
        if self.config_arn:
            self.msk.delete_configuration(Arn=self.config_arn)
            self.report['cleanup']['configuration'] = self.absent(self.msk,'describe_configuration','BadRequestException',Arn=self.config_arn)
        if self.queue:
            self.sqs.delete_queue(QueueUrl=self.queue)
            self.report['cleanup']['queue'] = True
        if self.role:
            for name in self.iam.list_role_policies(RoleName=self.role)['PolicyNames']:
                self.iam.delete_role_policy(RoleName=self.role, PolicyName=name)
            self.iam.delete_role(RoleName=self.role)
            self.report['cleanup']['role'] = True


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary', required=True)
    parser.add_argument('--protocol-probe', required=True)
    parser.add_argument('--state-directory', required=True)
    parser.add_argument('--docker-host', default='unix:///var/run/docker.sock')
    parser.add_argument('--telemetry-directory', default='/home/r/dev/minor/stackd/bin')
    Proof(parser.parse_args()).run()


if __name__ == '__main__':
    main()
