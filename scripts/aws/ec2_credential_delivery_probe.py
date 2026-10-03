#!/usr/bin/env python3
"""Capture IMDSv1/v2 credentials, IAM delivery conditions and cached-token validity.

One owned t3.nano, 8-GiB root, HTTPS-only egress, auto public IPv4, queue and
profile. No inbound access or standing/default mutations. Secrets remain in
guest memory; only material-equality booleans and public responses are emitted.
The experiment is bounded to 900 seconds and estimated below $0.01, not a bill.
"""
import json
import signal
import time

from ec2_instance_identity_probe import GUEST_HELPERS, IdentityCapture, run_identity_capture
from ec2_instances_probe import console_records
from ebs_encryption_probe import now, policy

DOC = 'https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instance-metadata-transition-to-version-2.html'
GUEST = GUEST_HELPERS + r'''
first = {}
for iteration in range(36):
    record = {'boot_id': boot, 'boot_count': boot_number, 'observation_id': boot + '-' + str(iteration),
              'iteration': iteration, 'at': time.time(), 'metadata': [], 'comparisons': [], 'signed': []}
    try:
        code, token, _ = http(base + 'api/token', headers={'X-aws-ec2-metadata-token-ttl-seconds': '60'}, method='PUT')
        if code != 200: raise RuntimeError('metadata token failed')
        current = {}
        for version, access in ((1, None), (2, token)):
            for actor, path in (('intrinsic', 'identity-credentials/ec2/security-credentials/ec2-instance'),
                                ('profile', 'iam/security-credentials/' + CONFIG['role'])):
                code, body, headers = metadata(path, access)
                row = {'actor': actor, 'metadata_version': version, 'status': code, 'content_type': headers.get('Content-Type')}
                if code == 200:
                    delivered = json.loads(body)
                    row['public'] = {key: delivered[key] for key in ('Code', 'Type', 'LastUpdated', 'Expiration', 'Message') if key in delivered}
                    if delivered.get('Code') == 'Success':
                        current[(actor, version)] = delivered
                        first.setdefault((actor, version), delivered)
                record['metadata'].append(row)
        for actor in ('intrinsic', 'profile'):
            if (actor, 1) in current and (actor, 2) in current:
                one, two = current[(actor, 1)], current[(actor, 2)]
                record['comparisons'].append({'actor': actor, **{field + '_equal': one[field] == two[field]
                    for field in ('AccessKeyId', 'SecretAccessKey', 'Token')}})
        v1 = next(row['status'] for row in record['metadata'] if row['actor'] == 'profile' and row['metadata_version'] == 1)
        record['phase'] = 'optional' if v1 == 200 else 'required' if v1 == 401 else 'waiting'
        samples = [('current', actor, version, material) for (actor, version), material in current.items()]
        if record['phase'] == 'required':
            samples.extend(('retained', actor, version, material) for (actor, version), material in first.items())
        for source, actor, version, material in samples:
            for service, action, parameters in (('sts', 'GetCallerIdentity', {}),
                    ('sqs', 'SendMessage', {'QueueUrl': CONFIG['queue'], 'MessageBody': 'owned-delivery-version'})):
                row = signed(material, service, action, parameters)
                row.update(source=source, actor=actor, metadata_version=version)
                record['signed'].append(row)
        del token, body, current, samples
    except Exception as error:
        record['error_type'] = type(error).__name__
    with open('/dev/console', 'w') as console:
        console.write('STACKD_GUEST ' + json.dumps(record, separators=(',', ':')) + '\n')
    if record.get('phase') == 'required' and 'error_type' not in record:
        break
    time.sleep(10)
'''


class DeliveryCapture(IdentityCapture):
    def delivery_console(self, iid: str, phase: str, seconds: int) -> dict:
        deadline = time.monotonic() + seconds
        seen = {row['guest']['observation_id'] for row in self.data['guest_observations']}
        for attempt in range(seconds // 10 + 1):
            label = phase + '-console-' + str(attempt)
            result = self.ec2(label, 'get_console_output', {'InstanceId': iid, 'Latest': True})
            for record in console_records(result.get('Output', '')):
                if record['observation_id'] not in seen:
                    seen.add(record['observation_id'])
                    self.data['guest_observations'].append({'instance': iid, 'call': label, 'guest': record})
                self.save()
                calls = record.get('signed', [])
                profile_v2 = any(row['actor'] == 'profile' and row['metadata_version'] == 2 and
                                 row['action'] == 'SendMessage' and row['status'] == 200 for row in calls)
                v1_source = 'current' if phase == 'optional' else 'retained'
                profile_v1 = any(row['actor'] == 'profile' and row['metadata_version'] == 1 and
                                 row['source'] == v1_source and row['action'] == 'GetCallerIdentity' and
                                 row['status'] == 200 for row in calls)
                if record.get('phase') == phase and profile_v1 and profile_v2 and 'error_type' not in record:
                    return record
            if time.monotonic() >= deadline:
                break
            time.sleep(10)
        raise RuntimeError('No complete signed delivery observation for ' + phase)

    def run(self):
        self.deadline = time.monotonic() + self.args.live_seconds
        signal.alarm(self.args.live_seconds)
        self.data.update(scope=__doc__, bounds={'max_simultaneous_instances': 1, 'experiment_seconds': self.args.live_seconds,
            'interface_endpoints': 0, 'internet_gateways': 1, 'queue_count': 1, 'root_gib': 8,
            'instance_type': 't3.nano', 'public_network': True, 'auto_public_ipv4': 1, 'estimated_cost_usd': 0.01})
        self.data['documentation'].append(DOC)
        config = self.setup_public_boundary()
        config['role'] = self.data['guest_role']
        deny_v1 = policy([{'Effect': 'Deny', 'Action': 'sqs:SendMessage', 'Resource': config['queue_arn'],
                          'Condition': {'NumericLessThan': {'ec2:RoleDelivery': '2.0'}}}])
        self.observe('owned-role-delivery-policy', 'iam', 'put_role_policy', {'RoleName': config['role'],
            'PolicyName': 'owned-delivery-version', 'PolicyDocument': json.dumps(deny_v1)}, required=True)
        self.observe('read-role-delivery-policy', 'iam', 'get_role_policy', {'RoleName': config['role'],
            'PolicyName': 'owned-delivery-version'}, required=True)
        guest = GUEST.replace('__CONFIG__', repr(config))
        self.data['guest_program'] = guest
        request = self.request()
        request['MetadataOptions']['HttpTokens'] = 'optional'
        iid = self.launch_public_guest('launch-delivery-versions', guest, request)
        self.state(iid, 'running', 'delivery-running')
        self.delivery_console(iid, 'optional', 240)
        self.ec2('require-v2', 'modify_instance_metadata_options', {'InstanceId': iid, 'HttpTokens': 'required'}, required=True)
        self.ec2('describe-required', 'describe_instances', {'InstanceIds': [iid]}, required=True)
        self.delivery_console(iid, 'required', 180)
        self.data['capture_complete_at'] = now()
        self.data['gaps'].extend(['Single account/region and one instance; no native lifetime distribution or rotation interval established.',
            'CloudTrail delivery is eventual; exact signed request-ID joins are captured separately after resource cleanup.'])
        self.save()

    def cleanup(self):
        signal.alarm(0)
        self.cleaning = True
        try:
            if self.data.get('guest_role'):
                self.observe('cleanup-delivery-policy', 'iam', 'delete_role_policy',
                    {'RoleName': self.data['guest_role'], 'PolicyName': 'owned-delivery-version'})
        finally:
            super().cleanup()


if __name__ == '__main__':
    run_identity_capture(DeliveryCapture, '.stackd/probes/ec2/credential_delivery_versions.json', __doc__)
