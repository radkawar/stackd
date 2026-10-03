#!/usr/bin/env python3
"""Capture EC2 role credential origin keys versus public endpoint network keys.

One owned t3.nano, 8-GiB root, HTTPS-only egress, auto public IPv4, profile and
12 queues. No inbound rules, standing/default mutations or exported credentials.
The 900-second experiment is estimated below USD 0.01, not an AWS bill.
"""
import json
import signal
import time

from ec2_instance_identity_probe import GUEST_HELPERS, IdentityCapture, run_identity_capture
from ec2_instances_probe import console_records
from ebs_encryption_probe import now, policy

DOC = 'https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_condition-keys.html'
CASES = ('policy-control', 'instance-match', 'instance-other', 'vpc-match', 'vpc-other',
         'ip-match', 'ip-other', 'endpoint-vpc-absent', 'endpoint-vpc-present',
         'endpoint-ip-absent', 'endpoint-ip-present')
GUEST = GUEST_HELPERS + r'''
complete = 0
for iteration in range(36):
    record = {'boot_id': boot, 'boot_count': boot_number, 'observation_id': boot + '-' + str(iteration),
              'iteration': iteration, 'at': time.time(), 'metadata': [], 'signed': []}
    try:
        code, token, _ = http(base + 'api/token', headers={'X-aws-ec2-metadata-token-ttl-seconds': '60'}, method='PUT')
        if code != 200: raise RuntimeError('metadata token failed')
        for version, access in ((1, None), (2, token)):
            code, body, _ = metadata('iam/security-credentials/' + CONFIG['role'], access)
            record['metadata'].append({'metadata_version': version, 'status': code})
            if code != 200: continue
            credentials = json.loads(body)
            if credentials.get('Code') != 'Success': continue
            identity = signed(credentials, 'sts', 'GetCallerIdentity', {})
            identity.update(actor='profile', metadata_version=version, source='current')
            record['signed'].append(identity)
            for label, url in CONFIG['queues'].items():
                result = signed(credentials, 'sqs', 'SendMessage', {'QueueUrl': url, 'MessageBody': 'owned-origin-context'})
                result.update(actor='profile', metadata_version=version, source='current', condition_case=label)
                record['signed'].append(result)
            del credentials, body
        controls = [row for row in record['signed'] if row.get('condition_case') in ('control', 'policy-control')]
        record['complete'] = (len(record['signed']) == 2 * (len(CONFIG['queues']) + 1) and
            len(controls) == 4 and all(row['status'] == 200 for row in controls) and
            all(row['status'] in (200, 403) for row in record['signed']))
        complete += int(record['complete'])
        del token
    except Exception as error:
        record['error_type'] = type(error).__name__
    with open('/dev/console', 'w') as console:
        console.write('STACKD_GUEST ' + json.dumps(record, separators=(',', ':')) + '\n')
    if complete == 3: break
    time.sleep(5)
'''


class OriginCapture(IdentityCapture):
    def run(self):
        self.deadline = time.monotonic() + self.args.live_seconds
        signal.alarm(self.args.live_seconds)
        self.data.update(scope=__doc__, bounds={'max_simultaneous_instances': 1,
            'experiment_seconds': self.args.live_seconds, 'interface_endpoints': 0,
            'internet_gateways': 1, 'queue_count': 12, 'root_gib': 8,
            'instance_type': 't3.nano', 'public_network': True, 'auto_public_ipv4': 1,
            'estimated_cost_usd': 0.01})
        self.data['documentation'].append(DOC)
        config = self.setup_public_boundary()
        config['role'] = self.data['guest_role']
        config['queues'] = {'control': config['queue']}
        owned = self.data['owned'].setdefault('origin_queues', {})
        for label in CASES:
            url = self.observe('owned-queue-' + label, 'sqs', 'create_queue',
                {'QueueName': self.data['prefix'] + '-' + label, 'tags': {'suite': self.data['prefix']}}, required=True)['QueueUrl']
            owned[label] = url
            config['queues'][label] = url
            self.save()
        guest = GUEST.replace('__CONFIG__', repr(config))
        self.data['guest_program'] = guest
        request = self.request()
        request['MetadataOptions']['HttpTokens'] = 'optional'
        iid = self.launch_public_guest('launch-origin-context', guest, request)
        instance = self.ec2('origin-instance-facts', 'describe_instances', {'InstanceIds': [iid]}, required=True)['Reservations'][0]['Instances'][0]
        arn = 'arn:aws:ec2:' + self.args.region + ':' + self.args.account + ':instance/' + iid
        vpc, address = instance['VpcId'], instance['PrivateIpAddress']
        conditions = {
            'instance-match': {'ArnEquals': {'ec2:SourceInstanceARN': arn}},
            'instance-other': {'ArnEquals': {'ec2:SourceInstanceARN': 'arn:aws:ec2:' + self.args.region + ':' + self.args.account + ':instance/i-00000000000000000'}},
            'vpc-match': {'StringEquals': {'aws:Ec2InstanceSourceVpc': vpc}},
            'vpc-other': {'StringEquals': {'aws:Ec2InstanceSourceVpc': 'vpc-00000000000000000'}},
            'ip-match': {'IpAddress': {'aws:Ec2InstanceSourcePrivateIPv4': address}, 'StringEquals': {'aws:Ec2InstanceSourceVpc': vpc}},
            'ip-other': {'IpAddress': {'aws:Ec2InstanceSourcePrivateIPv4': '192.0.2.37'}, 'StringEquals': {'aws:Ec2InstanceSourceVpc': vpc}},
            'endpoint-vpc-absent': {'Null': {'aws:SourceVpc': 'true'}},
            'endpoint-vpc-present': {'Null': {'aws:SourceVpc': 'false'}},
            'endpoint-ip-absent': {'Null': {'aws:VpcSourceIp': 'true'}},
            'endpoint-ip-present': {'Null': {'aws:VpcSourceIp': 'false'}},
            'policy-control': {},
        }
        self.data['origin_conditions'] = conditions
        self.data['origin_facts'] = {'instance_arn': arn, 'vpc_id': vpc, 'private_ipv4': address}
        self.save()
        statements = []
        for label, condition in conditions.items():
            url = owned[label]
            queue_arn = self.observe('queue-arn-' + label, 'sqs', 'get_queue_attributes',
                {'QueueUrl': url, 'AttributeNames': ['QueueArn']}, required=True)['Attributes']['QueueArn']
            statement = {'Effect': 'Allow', 'Action': 'sqs:SendMessage', 'Resource': queue_arn}
            if condition:
                statement['Condition'] = condition
            statements.append(statement)
        self.observe('owned-origin-policy', 'iam', 'put_role_policy', {'RoleName': config['role'],
            'PolicyName': 'owned-credential-origin', 'PolicyDocument': json.dumps(policy(statements))}, required=True)
        self.observe('read-origin-policy', 'iam', 'get_role_policy', {'RoleName': config['role'],
            'PolicyName': 'owned-credential-origin'}, required=True)
        self.state(iid, 'running', 'origin-running')
        seen = set()
        deadline = time.monotonic() + 240
        for attempt in range(25):
            label = 'origin-console-' + str(attempt)
            output = self.ec2(label, 'get_console_output', {'InstanceId': iid, 'Latest': True})
            for record in console_records(output.get('Output', '')):
                if record['observation_id'] not in seen:
                    seen.add(record['observation_id'])
                    self.data['guest_observations'].append({'instance': iid, 'call': label, 'guest': record})
            self.save()
            if sum(bool(row['guest'].get('complete')) for row in self.data['guest_observations']) >= 3:
                self.data['capture_complete_at'] = now()
                self.data['gaps'].extend(['One account/region and primary IPv4 interface; no VPC endpoint, forwarding or chained-role context established.',
                    'Queue-policy publication timing is not inferred from these settled samples.'])
                self.save()
                return
            if time.monotonic() >= deadline: break
            time.sleep(10)
        raise RuntimeError('No complete native origin-context observations')

    def cleanup(self):
        signal.alarm(0)
        self.cleaning = True
        failures = []
        if self.data.get('guest_role'):
            self.observe('cleanup-origin-policy', 'iam', 'delete_role_policy',
                {'RoleName': self.data['guest_role'], 'PolicyName': 'owned-credential-origin'})
        for label, url in self.data['owned'].get('origin_queues', {}).items():
            self.observe('cleanup-origin-queue-' + label, 'sqs', 'delete_queue', {'QueueUrl': url})
            self.observe('cleanup-origin-queue-absence-' + label, 'sqs', 'get_queue_attributes',
                {'QueueUrl': url, 'AttributeNames': ['QueueArn']})
            if self.data['calls'][-1]['code'] not in ('AWS.SimpleQueueService.NonExistentQueue', 'QueueDoesNotExist'):
                failures.append({'origin_queue': url})
        try:
            super().cleanup()
        finally:
            self.data['cleanup']['failures'].extend(failures)
            self.data['cleanup']['complete'] = self.data['cleanup'].get('complete', False) and not failures
            self.save()
        if failures: raise RuntimeError('Owned origin queue cleanup incomplete')


if __name__ == '__main__':
    run_identity_capture(OriginCapture, '.stackd/probes/ec2/credential_origin_context.json', __doc__)
