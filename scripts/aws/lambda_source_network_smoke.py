#!/usr/bin/env python3
"""Owned signed EC2 -> self-managed Kafka VPC poller -> native Lambda -> SQS.

The broker is an actual user-managed Apache Kafka fixture with an EC2-reserved
private address. It has no host-published listener. Only the producer/admin CLI
runs inside the broker; Lambda receives its private advertised listener.

Network selection and execution-role requirements:
https://docs.aws.amazon.com/lambda/latest/dg/with-kafka-cluster-network.html
https://docs.aws.amazon.com/lambda/latest/dg/with-kafka-permissions.html
"""
import argparse
import base64
import hashlib
import io
import json
import subprocess
import time
import zipfile

from botocore.exceptions import ClientError
from lambda_msk_executable_smoke import LambdaProof, HANDLER
from msk_executable_smoke import require

KAFKA_IMAGE = 'apache/kafka@sha256:ed74d7d115968d5e8b00ba6822ac6a384cbaaf54ca38991828647000d7089b68'
TOOLKIT_IMAGE = 'nicolaka/netshoot@sha256:47b907d662d139d1e2f22bfe14f4efca1e3f1feed283572f47c970c780c03b61'


class SourceNetworkProof(LambdaProof):
    runtime_selectors = ()

    def __init__(self, args):
        super().__init__(args)
        self.ec2 = self.client('ec2')
        self.vpc = self.source_subnet = self.broker_subnet = self.sg = None
        self.broker_eni = self.acl = self.bridge = self.broker = None
        self.mapping_arn = None
        self.cidr = args.cidr
        import ipaddress
        pool = ipaddress.ip_network(self.cidr)
        require(pool.version == 4 and pool.prefixlen == 24, 'owned proof requires an IPv4 /24')
        self.gateway, self.dns = str(pool[1]), str(pool[2])
        self.broker_ip = str(pool[132])
        self.source_cidr, self.broker_cidr = map(str, pool.subnets(new_prefix=25))
        self.permission = {'IpProtocol': 'tcp', 'FromPort': 9092, 'ToPort': 9092,
                           'IpRanges': [{'CidrIp': self.broker_ip + '/32'}]}

    def docker(self, *args, input=None, timeout=60, check=True):
        result = subprocess.run(['docker', '--host', self.args.docker_host, *args], input=input,
            text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
        if check:
            require(result.returncode == 0, 'native command failed: ' + result.stderr)
        return result

    def kafka(self, tool, *args, input=None, check=True):
        return self.docker('exec', '-i', self.broker, '/opt/kafka/bin/kafka-' + tool + '.sh',
            '--bootstrap-server', '127.0.0.1:9092', *args, input=input, check=check)

    def produce(self, identifier, fail=False):
        self.kafka('console-producer', '--topic', self.prefix,
                   input=json.dumps({'id': identifier, 'fail': fail}) + '\n')

    def committed(self):
        result = self.kafka('consumer-groups', '--describe', '--group', self.group, check=False)
        for line in result.stdout.splitlines():
            columns = line.split()
            if len(columns) >= 4 and columns[:3] == [self.group, self.prefix, '0']:
                return int(columns[3]) if columns[3] != '-' else -1
        return -1

    def next_observation(self, identifier, successful=True):
        return self.take(lambda row: (not successful or not row['fail']) and any(
            json.loads(base64.b64decode(record['value'])).get('id') == identifier
            for records in row['event']['records'].values() for record in records))

    def checkpoint(self, offset):
        return self.wait(lambda: self.committed() == offset, 'broker committed offset ' + str(offset))

    def quiet(self, offset):
        for _ in range(4):
            require(self.receive() is None, 'network/role denial allowed a Lambda target effect')
        require(self.committed() == offset, 'network/role denial advanced the broker checkpoint')

    def setup_network(self):
        self.vpc = self.ec2.create_vpc(CidrBlock=self.cidr)['Vpc']['VpcId']
        self.source_subnet = self.ec2.create_subnet(VpcId=self.vpc, CidrBlock=self.source_cidr)['Subnet']['SubnetId']
        self.broker_subnet = self.ec2.create_subnet(VpcId=self.vpc, CidrBlock=self.broker_cidr)['Subnet']['SubnetId']
        self.sg = self.ec2.create_security_group(VpcId=self.vpc, GroupName=self.prefix,
                                               Description='Owned Lambda source VPC proof')['GroupId']
        initial = self.ec2.describe_security_groups(GroupIds=[self.sg])['SecurityGroups'][0]['IpPermissionsEgress']
        if initial:
            self.ec2.revoke_security_group_egress(GroupId=self.sg, IpPermissions=initial)
        self.ec2.authorize_security_group_egress(GroupId=self.sg, IpPermissions=[self.permission])
        interface = self.ec2.create_network_interface(SubnetId=self.broker_subnet, PrivateIpAddress=self.broker_ip,
            Description=self.prefix + ' self-managed broker reservation')['NetworkInterface']
        self.broker_eni = interface['NetworkInterfaceId']
        network_arn = 'arn:aws:ec2:us-east-1:000000000000:vpc/' + self.vpc
        self.bridge = 'stackd-ecs-network-' + hashlib.sha256(network_arn.encode()).hexdigest()
        self.docker('network', 'create', '--driver', 'bridge', '--subnet', self.cidr, '--gateway', self.gateway,
            '--aux-address', 'amazon-dns=' + self.dns, '--label', 'stackd.ecs.network=' + network_arn, self.bridge)
        self.acl = next(acl['NetworkAclId'] for acl in self.ec2.describe_network_acls(
            Filters=[{'Name': 'vpc-id', 'Values': [self.vpc]}])['NetworkAcls'] if acl['IsDefault'])
        self.broker = self.prefix + '-vpc-broker'
        environment = {
            'KAFKA_NODE_ID': '1', 'KAFKA_PROCESS_ROLES': 'broker,controller',
            'KAFKA_LISTENERS': 'PLAINTEXT://0.0.0.0:9092,CONTROLLER://0.0.0.0:9093',
            'KAFKA_ADVERTISED_LISTENERS': 'PLAINTEXT://' + self.broker_ip + ':9092',
            'KAFKA_CONTROLLER_LISTENER_NAMES': 'CONTROLLER',
            'KAFKA_LISTENER_SECURITY_PROTOCOL_MAP': 'CONTROLLER:PLAINTEXT,PLAINTEXT:PLAINTEXT',
            'KAFKA_CONTROLLER_QUORUM_VOTERS': '1@127.0.0.1:9093',
            'KAFKA_OFFSETS_TOPIC_REPLICATION_FACTOR': '1',
            'KAFKA_TRANSACTION_STATE_LOG_REPLICATION_FACTOR': '1',
            'KAFKA_TRANSACTION_STATE_LOG_MIN_ISR': '1', 'KAFKA_GROUP_INITIAL_REBALANCE_DELAY_MS': '0',
            'KAFKA_HEAP_OPTS': '-Xmx256m -Xms256m'}
        command = ['run', '-d', '--name', self.broker, '--network', self.bridge, '--ip', self.broker_ip,
                   '--mac-address', interface['MacAddress'], '--label', 'stackd.lambda.source-proof=' + self.prefix,
                   '--memory', '768m', '--memory-swap', '768m', '--pids-limit', '256']
        for key, value in environment.items():
            command += ['--env', key + '=' + value]
        self.docker(*command, KAFKA_IMAGE)
        self.wait(lambda: self.kafka('topics', '--list', check=False).returncode == 0, 'owned private broker', 120)
        self.kafka('topics', '--create', '--topic', self.prefix, '--partitions', '1', '--replication-factor', '1')

    def setup_function(self):
        self.queue = self.sqs.create_queue(QueueName=self.prefix)['QueueUrl']
        queue_arn = self.sqs.get_queue_attributes(QueueUrl=self.queue, AttributeNames=['QueueArn'])['Attributes']['QueueArn']
        self.role = self.prefix
        role = self.iam.create_role(RoleName=self.role, AssumeRolePolicyDocument=json.dumps({
            'Version': '2012-10-17', 'Statement': [{'Effect': 'Allow', 'Principal': {'Service': 'lambda.amazonaws.com'},
                                                'Action': 'sts:AssumeRole'}]}))['Role']['Arn']
        self.iam.put_role_policy(RoleName=self.role, PolicyName='source-target', PolicyDocument=json.dumps({
            'Version': '2012-10-17', 'Statement': [
                {'Effect': 'Allow', 'Action': 'sqs:SendMessage', 'Resource': queue_arn},
                {'Effect': 'Allow', 'Action': ['logs:CreateLogGroup', 'logs:CreateLogStream', 'logs:PutLogEvents'], 'Resource': '*'},
                {'Effect': 'Allow', 'Action': ['ec2:CreateNetworkInterface', 'ec2:DeleteNetworkInterface',
                    'ec2:DescribeNetworkInterfaces', 'ec2:DescribeSubnets', 'ec2:DescribeSecurityGroups', 'ec2:DescribeVpcs'], 'Resource': '*'},
                {'Effect': 'Deny', 'Action': 'kafka:*', 'Resource': '*'}]}))
        package = io.BytesIO()
        with zipfile.ZipFile(package, 'w') as archive:
            archive.writestr('entry.py', HANDLER)
        self.function = self.prefix
        self.functions.create_function(FunctionName=self.function, Runtime='python3.12', Handler='entry.invoke', Role=role,
            Code={'ZipFile': package.getvalue()}, Timeout=20, MemorySize=128, Environment=self.environment('1'))
        self.wait(self.function_ready, 'real Python function')
        return dict(FunctionName=self.function, Topics=[self.prefix], StartingPosition='TRIM_HORIZON', BatchSize=1,
            MaximumBatchingWindowInSeconds=0, SelfManagedEventSource={'Endpoints': {'KAFKA_BOOTSTRAP_SERVERS': [self.broker_ip + ':9092']}},
            SelfManagedKafkaEventSourceConfig={'ConsumerGroupId': self.group}, SourceAccessConfigurations=[
                {'Type': 'VPC_SUBNET', 'URI': 'subnet:' + self.source_subnet},
                {'Type': 'VPC_SECURITY_GROUP', 'URI': 'security_group:' + self.sg}])

    def deny(self, action):
        self.iam.put_role_policy(RoleName=self.role, PolicyName='deny-network', PolicyDocument=json.dumps({
            'Version': '2012-10-17', 'Statement': [{'Effect': 'Deny', 'Action': action, 'Resource': '*'}]}))

    def cleanup(self):
        if self.role:
            policies = self.iam.list_role_policies(RoleName=self.role)['PolicyNames']
            if 'deny-network' in policies:
                self.iam.delete_role_policy(RoleName=self.role, PolicyName='deny-network')
        super().cleanup()
        if self.vpc:
            interfaces = self.ec2.describe_network_interfaces(Filters=[{'Name': 'vpc-id', 'Values': [self.vpc]}])['NetworkInterfaces']
            require([row['NetworkInterfaceId'] for row in interfaces] == [self.broker_eni], 'mapping ENI leaked after retirement')
            self.report['cleanup']['mapping_eni'] = True
        if self.mapping_arn:
            native = self.docker('ps', '-a', '--filter', 'label=stackd.lambda.source-network=' + self.mapping_arn, '--format', '{{.ID}}')
            require(not native.stdout.strip(), 'mapping native namespace leaked')
            self.report['cleanup']['source_namespace'] = True
            namespace = 'stackd-lambda-sources-' + hashlib.sha256(str(self.state / 'msk.sqlite').encode()).hexdigest()[:24]
            table = 'stackd_lambda_' + hashlib.sha256((namespace + '\0' + self.mapping_arn).encode()).hexdigest()
            rules = self.docker('run', '--rm', '--name', self.prefix + '-policy-inspection',
                '--network', 'host', '--cap-drop', 'ALL', '--cap-add', 'NET_ADMIN',
                '--security-opt', 'no-new-privileges:true', '--read-only', '--memory', '64m',
                '--memory-swap', '64m', '--pids-limit', '32', '--label', 'stackd.lambda.source-proof=' + self.prefix,
                TOOLKIT_IMAGE, 'nft', '-j', 'list', 'tables')
            require(not any(row.get('table', {}).get('name') == table for row in json.loads(rules.stdout)['nftables']),
                    'mapping native packet-policy table leaked')
            self.report['cleanup']['source_packet_policy'] = True
        if self.broker:
            mounted = json.loads(self.docker('inspect', self.broker).stdout)[0]['Mounts']
            volumes = [mount['Name'] for mount in mounted if mount['Type'] == 'volume']
            self.docker('rm', '-fv', self.broker)
            for volume in volumes:
                remaining = self.docker('volume', 'ls', '--filter', 'name=' + volume, '--format', '{{.Name}}')
                require(volume not in remaining.stdout.splitlines(), 'owned anonymous broker volume leaked')
            self.report['cleanup']['broker_volumes_removed'] = len(volumes)
            self.report['cleanup']['broker'] = True
        if self.bridge:
            self.docker('network', 'rm', self.bridge)
            self.report['cleanup']['bridge'] = True
        if self.broker_eni:
            self.ec2.delete_network_interface(NetworkInterfaceId=self.broker_eni)
        if self.sg:
            self.ec2.delete_security_group(GroupId=self.sg)
        for subnet in (self.source_subnet, self.broker_subnet):
            if subnet:
                self.ec2.delete_subnet(SubnetId=subnet)
        if self.vpc:
            self.ec2.delete_vpc(VpcId=self.vpc)
            self.report['cleanup']['vpc'] = True

    def run(self):
        self.start()
        try:
            self.setup_network()
            config = self.setup_function()
            self.deny('ec2:CreateNetworkInterface')
            try:
                self.functions.create_event_source_mapping(**config)
            except ClientError as error:
                self.report['observations']['eni_admission_denied'] = error.response['Error']
            else:
                raise AssertionError('mapping ignored current CreateNetworkInterface denial')
            require(len(self.ec2.describe_network_interfaces(Filters=[{'Name': 'vpc-id', 'Values': [self.vpc]}])['NetworkInterfaces']) == 1,
                    'failed admission leaked a source ENI')
            self.iam.delete_role_policy(RoleName=self.role, PolicyName='deny-network')
            created = self.functions.create_event_source_mapping(**config)
            self.mapping, self.mapping_arn = created['UUID'], created['EventSourceMappingArn']
            self.wait(lambda: self.mapping_state('Enabled'), 'VPC mapping enabled')
            eni = next(row for row in self.ec2.describe_network_interfaces(Filters=[{'Name': 'subnet-id', 'Values': [self.source_subnet]}])['NetworkInterfaces'])
            require(eni['RequesterManaged'] and eni['Status'] == 'in-use', 'source ENI is not owned by Lambda')
            self.report['observations']['source_eni'] = eni
            self.produce('first')
            first = self.wait(lambda: self.next_observation('first'), 'native VPC Lambda -> SQS', 180)
            self.checkpoint(1)
            self.report['observations']['first_effect'] = first
            self.functions.update_event_source_mapping(UUID=self.mapping, BatchSize=1)
            self.wait(lambda: self.mapping_state('Enabled'), 'concurrent VPC preflight update')
            self.ec2.revoke_security_group_egress(GroupId=self.sg, IpPermissions=[self.permission])
            time.sleep(2)
            self.produce('sg-restored')
            self.quiet(1)
            self.ec2.authorize_security_group_egress(GroupId=self.sg, IpPermissions=[self.permission])
            self.report['observations']['sg_recovery'] = self.wait(lambda: self.next_observation('sg-restored'), 'SG recovery', 180)
            self.checkpoint(2)
            self.ec2.create_network_acl_entry(NetworkAclId=self.acl, RuleNumber=50, Protocol='6', RuleAction='deny',
                Egress=True, CidrBlock=self.broker_ip + '/32', PortRange={'From': 9092, 'To': 9092})
            time.sleep(2)
            self.produce('acl-restored')
            self.quiet(2)
            self.ec2.delete_network_acl_entry(NetworkAclId=self.acl, RuleNumber=50, Egress=True)
            self.report['observations']['acl_recovery'] = self.wait(lambda: self.next_observation('acl-restored'), 'NACL recovery', 180)
            self.checkpoint(3)
            self.deny('ec2:DescribeNetworkInterfaces')
            time.sleep(2)
            self.produce('role-restored')
            self.quiet(3)
            self.iam.delete_role_policy(RoleName=self.role, PolicyName='deny-network')
            self.report['observations']['role_recovery'] = self.wait(lambda: self.next_observation('role-restored'), 'current role recovery', 180)
            self.checkpoint(4)
            self.produce('restart-retry', fail=True)
            self.wait(lambda: self.next_observation('restart-retry', successful=False), 'real failed Lambda effect', 180)
            require(self.committed() == 4, 'failed invocation advanced checkpoint')
            self.stop()
            self.start()
            recovered_eni = self.ec2.describe_network_interfaces(NetworkInterfaceIds=[eni['NetworkInterfaceId']])['NetworkInterfaces'][0]
            require(recovered_eni['PrivateIpAddress'] == eni['PrivateIpAddress'], 'restart changed retained source ENI')
            self.functions.update_function_configuration(FunctionName=self.function, Environment=self.environment('0'))
            self.wait(self.function_ready, 'real runtime recovery')
            self.report['observations']['restart_recovery'] = self.wait(lambda: self.next_observation('restart-retry'), 'restart redelivery', 180)
            self.checkpoint(5)
            self.report['observations']['final_offset'] = 5
            print('PASS signed EC2 VPC -> Kafka -> real Lambda -> SQS; SG/NACL/IAM recovery; restart offset 5', flush=True)
        finally:
            try:
                if self.process:
                    self.capture_diagnostics()
                    self.cleanup()
            finally:
                self.stop()
                report = self.state / 'lambda-source-network-report.json'
                report.write_text(json.dumps(self.report, default=str, indent=2) + '\n')
        print(json.dumps({'report': str(report), 'cleanup': self.report['cleanup']}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', required=True)
    parser.add_argument('--state-directory', required=True)
    parser.add_argument('--docker-host', default='unix:///var/run/docker.sock')
    parser.add_argument('--telemetry-directory', default='/home/r/dev/minor/stackd/bin')
    parser.add_argument('--cidr', default='10.248.168.0/24')
    SourceNetworkProof(parser.parse_args()).run()


if __name__ == '__main__':
    main()
