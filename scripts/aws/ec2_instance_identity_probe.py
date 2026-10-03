#!/usr/bin/env python3
"""Capture one owned nano's intrinsic credentials without exporting secret material.

One owned IGW, HTTPS-only outbound networking, one auto-assigned public IPv4 and
one owned queue exercise an explicit resource grant with a profile positive
control. No inbound rules, standing resources or account defaults are changed.
One capture is estimated below $0.01; 900-second experiment and
bounded independently checked cleanup. Earlier private-transport failures remain
separate evidence, not authorization outcomes.
"""
import argparse
import base64
import json
from pathlib import Path
import signal
import time

from cloudtrail_events import CollectionError, collect_history
from ec2_instances_probe import InstanceCapture, console_records, interrupt
from ebs_encryption_probe import CONFIG, now, policy, safe

DOC = "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/iam-roles-for-amazon-ec2.html#ec2-instance-identity-roles"
GUEST_HELPERS = r'''#!/usr/bin/python3
import datetime, hashlib, hmac, json, pathlib, socket, ssl, time, urllib.request, urllib.error
CONFIG = __CONFIG__
boot = pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip()
counter = pathlib.Path('/var/lib/stackd-identity-boot-count')
boot_number = int(counter.read_text()) + 1 if counter.exists() else 1
counter.write_text(str(boot_number))
base = 'http://169.254.169.254/latest/'
def http(url, data=None, headers=None, method=None):
    try:
        response = urllib.request.urlopen(urllib.request.Request(url, data=data, headers=headers or {}, method=method), timeout=8)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        return response.status, response.read().decode(), dict(response.headers)
def metadata(path, token):
    return http(base + 'meta-data/' + path, headers={} if token is None else {'X-aws-ec2-metadata-token': token})
def transport(host):
    result = {'host': host, 'phase': 'dns'}
    try:
        result['addresses'] = sorted({row[4][0] for row in socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)})
        result['phase'] = 'tcp'
        with socket.create_connection((host, 443), timeout=8) as connection:
            result['phase'] = 'tls'
            with ssl.create_default_context().wrap_socket(connection, server_hostname=host) as secure:
                result['tls_version'] = secure.version()
        result['phase'] = 'ready'
    except Exception as error:
        result['error_type'] = type(error).__name__
        result['error'] = str(error)
    return result
def signed(credentials, service, action, parameters):
    host = CONFIG[service]
    timestamp = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    date = timestamp[:8]
    scope = date + '/us-east-1/' + service + '/aws4_request'
    headers = {'host': host, 'x-amz-date': timestamp, 'x-amz-security-token': credentials['Token']}
    if service == 'sts':
        body = ('Action=' + action + '&Version=2011-06-15').encode()
        headers['content-type'] = 'application/x-www-form-urlencoded; charset=utf-8'
    else:
        body = json.dumps(parameters, separators=(',', ':')).encode()
        headers['content-type'] = 'application/x-amz-json-1.0'
        headers['x-amz-target'] = 'AmazonSQS.' + action
    names = ';'.join(sorted(headers))
    canonical = 'POST\n/\n\n' + ''.join(k + ':' + headers[k] + '\n' for k in sorted(headers)) + '\n' + names + '\n' + hashlib.sha256(body).hexdigest()
    to_sign = 'AWS4-HMAC-SHA256\n' + timestamp + '\n' + scope + '\n' + hashlib.sha256(canonical.encode()).hexdigest()
    key = ('AWS4' + credentials['SecretAccessKey']).encode()
    for value in (date, 'us-east-1', service, 'aws4_request'):
        key = hmac.new(key, value.encode(), hashlib.sha256).digest()
    signature = hmac.new(key, to_sign.encode(), hashlib.sha256).hexdigest()
    headers['authorization'] = 'AWS4-HMAC-SHA256 Credential=' + credentials['AccessKeyId'] + '/' + scope + ', SignedHeaders=' + names + ', Signature=' + signature
    code, response, received = http('https://' + host + '/', data=body, headers=headers)
    # This allowlist is before console serialization, not host-side redaction.
    if code == 200 and action != 'GetCallerIdentity' and service == 'sts':
        response = '<successful response withheld: may contain credentials>'
    for field in ('AccessKeyId', 'SecretAccessKey', 'Token'):
        response = response.replace(credentials[field], '<redacted>')
    return {'service': service, 'action': action, 'status': code, 'body': response,
            'request_id': received.get('x-amzn-RequestId') or received.get('x-amzn-requestid')}
'''
GUEST = GUEST_HELPERS + r'''
last_key = None
for iteration in range(36):
    record = {'boot_id': boot, 'boot_count': boot_number, 'observation_id': boot + '-' + str(iteration), 'phase': 'without-profile', 'iteration': iteration, 'at': time.time(), 'metadata': [], 'signed': []}
    if iteration == 0:
        record['transport'] = [transport(CONFIG[service]) for service in ('sts', 'sqs')]
        record['network'] = {'kernel_routes': pathlib.Path('/proc/net/route').read_text(), 'resolvers': pathlib.Path('/etc/resolv.conf').read_text()}
    try:
        code, token, _ = http(base + 'api/token', headers={'X-aws-ec2-metadata-token-ttl-seconds': '60'}, method='PUT')
        if code != 200: raise RuntimeError('metadata token failed')
        for path in ('identity-credentials', 'identity-credentials/', 'identity-credentials/ec2', 'identity-credentials/ec2/', 'identity-credentials/ec2/info', 'identity-credentials/ec2/security-credentials', 'identity-credentials/ec2/security-credentials/'):
            code, body, headers = metadata(path, token)
            record['metadata'].append({'path': path, 'status': code, 'body': body, 'content_type': headers.get('Content-Type')})
        path = 'identity-credentials/ec2/security-credentials/ec2-instance'
        code, body, headers = metadata(path, token)
        intrinsic = json.loads(body) if code == 200 else {}
        record['metadata'].append({'path': path, 'status': code, 'content_type': headers.get('Content-Type'), 'fields': sorted(intrinsic), 'body': {k: intrinsic[k] for k in ('Code','Type','LastUpdated','Expiration','Message') if k in intrinsic}})
        record['intrinsic_key_changed'] = last_key is not None and last_key != intrinsic.get('AccessKeyId')
        last_key = intrinsic.get('AccessKeyId')
        code, role, _ = metadata('iam/security-credentials/', token)
        record['profile_directory_status'] = code
        actors = [('intrinsic', intrinsic)]
        if code == 200:
            code, body, _ = metadata('iam/security-credentials/' + role.strip(), token)
            if code == 200:
                attached = json.loads(body)
                if attached.get('Code') == 'Success':
                    actors.append(('profile', attached))
                    record['phase'] = 'with-profile' if boot_number == 1 else 'after-start'
                    record['distinct_profile_credentials'] = intrinsic.get('AccessKeyId') != attached.get('AccessKeyId')
        for actor, credentials in actors:
            if credentials.get('Code') != 'Success': continue
            for service, action, parameters in (('sts','GetCallerIdentity',{}), ('sts','GetSessionToken',{}), ('sqs','SendMessage',{'QueueUrl':CONFIG['queue'], 'MessageBody':'owned-intrinsic-boundary'})):
                try:
                    row = signed(credentials, service, action, parameters)
                except Exception as error:
                    row = {'service': service, 'action': action, 'status': 0, 'error_type': type(error).__name__}
                    record['error_type'] = type(error).__name__
                    if isinstance(error, urllib.error.URLError):
                        row.update(transport_reason_type=type(error.reason).__name__, transport_reason=str(error.reason))
                row['actor'] = actor
                record['signed'].append(row)
        del token, body, actors, intrinsic
    except Exception as error:
        record['error_type'] = type(error).__name__
        if isinstance(error, urllib.error.URLError):
            record['transport_reason_type'] = type(error.reason).__name__
            record['transport_reason'] = str(error.reason)
    with open('/dev/console', 'w') as console:
        console.write('STACKD_GUEST ' + json.dumps(record, separators=(',', ':')) + '\n')
    if record['phase'] != 'without-profile' and 'error_type' not in record: break
    time.sleep(10)
'''


class IdentityCapture(InstanceCapture):
    def __init__(self, args):
        super().__init__(args)
        self.clients['sqs'] = self.session.client('sqs', config=CONFIG)

    def identity_console(self, iid, label, seconds):
        deadline = time.monotonic() + seconds
        for attempt in range(seconds // 10 + 1):
            result = self.ec2(label + '-' + str(attempt), 'get_console_output', {'InstanceId': iid, 'Latest': True})
            for record in console_records(result.get('Output', '')):
                if not any(row['guest'].get('observation_id', row['guest']['boot_id']) == record['observation_id'] for row in self.data['guest_observations']):
                    self.data['guest_observations'].append({'instance': iid, 'call': label + '-' + str(attempt), 'guest': record})
                self.save()
                ready = any(row['actor'] == 'intrinsic' and row['action'] == 'GetCallerIdentity' and row['status'] == 200 for row in record.get('signed', []))
                if record['phase'] == label and ready and 'error_type' not in record:
                    return record
            if time.monotonic() >= deadline: return None
            time.sleep(10)

    def setup_public_boundary(self) -> dict[str, str]:
        self.setup()
        owned = self.data['owned']
        group = owned['group']
        gateway = self.ec2('owned-internet-gateway', 'create_internet_gateway', {'TagSpecifications': self.tags('internet-gateway')}, required=True)['InternetGateway']['InternetGatewayId']
        owned['internet_gateway'] = gateway
        self.save()
        self.ec2('owned-internet-gateway-attach', 'attach_internet_gateway', {'InternetGatewayId': gateway, 'VpcId': owned['vpc']}, required=True)
        tables = self.ec2('owned-public-route-table', 'describe_route_tables', {'Filters': [{'Name': 'vpc-id', 'Values': [owned['vpc']]}]}, required=True)['RouteTables']
        if len(tables) != 1: raise RuntimeError('Owned VPC main route-table ownership ambiguous')
        owned['route_table'] = tables[0]['RouteTableId']
        self.save()
        self.ec2('owned-https-egress-route', 'create_route', {'RouteTableId': owned['route_table'], 'DestinationCidrBlock': '0.0.0.0/0', 'GatewayId': gateway}, required=True)
        self.ec2('owned-https-egress-security', 'authorize_security_group_egress', {'GroupId': group, 'IpPermissions': [
            {'IpProtocol': 'tcp', 'FromPort': 443, 'ToPort': 443, 'IpRanges': [{'CidrIp': '0.0.0.0/0'}]}]}, required=True)
        self.ec2('owned-public-security', 'describe_security_groups', {'GroupIds': [group]}, required=True)
        config = {service: service + '.us-east-1.amazonaws.com' for service in ('sts', 'sqs')}
        queue = self.observe('owned-boundary-queue', 'sqs', 'create_queue', {'QueueName': self.data['prefix'], 'tags': {'suite': self.data['prefix']}}, required=True)['QueueUrl']
        owned['queue'] = queue
        self.save()
        arn = self.observe('owned-queue-arn', 'sqs', 'get_queue_attributes', {'QueueUrl': queue, 'AttributeNames': ['QueueArn']}, required=True)['Attributes']['QueueArn']
        grant = policy([{'Effect': 'Allow', 'Principal': '*', 'Action': 'sqs:SendMessage', 'Resource': arn,
            'Condition': {'StringEquals': {'aws:PrincipalAccount': self.args.account}}}])
        self.observe('owned-account-resource-grant', 'sqs', 'set_queue_attributes', {'QueueUrl': queue, 'Attributes': {'Policy': json.dumps(grant)}}, required=True)
        self.observe('read-resource-grant', 'sqs', 'get_queue_attributes', {'QueueUrl': queue, 'AttributeNames': ['Policy']}, required=True)
        config['queue'] = queue
        config['queue_arn'] = arn
        return config

    def launch_public_guest(self, label: str, guest: str, request: dict) -> str:
        request['BlockDeviceMappings'] = request['BlockDeviceMappings'][:1]
        request['BlockDeviceMappings'][0]['Ebs']['DeleteOnTermination'] = True
        # These bounded credential captures own their public networking;
        # the shared request helper remains private.
        request['NetworkInterfaces'][0]['AssociatePublicIpAddress'] = True
        request['UserData'] = "#!/bin/bash\nset -eu\numask 077\nprintf '%s' '" + base64.b64encode(guest.encode()).decode() + "' | base64 -d > /root/stackd-identity-probe.py\ncat > /etc/systemd/system/stackd-identity-probe.service <<'UNIT'\n[Unit]\nWants=network-online.target\nAfter=network-online.target\n[Service]\nType=oneshot\nExecStart=/usr/bin/python3 /root/stackd-identity-probe.py\nTimeoutStartSec=500\n[Install]\nWantedBy=multi-user.target\nUNIT\nsystemctl daemon-reload\nsystemctl enable --now stackd-identity-probe.service\n"
        if self.data['owned']['instances']: raise RuntimeError('One-instance ownership guard')
        return self.launch(label, request, required=True)['Instances'][0]['InstanceId']

    def run(self):
        self.deadline = time.monotonic() + self.args.live_seconds
        signal.alarm(self.args.live_seconds)
        self.data.update(scope=__doc__, bounds={'max_simultaneous_instances': 1, 'experiment_seconds': self.args.live_seconds,
            'cleanup_poll_seconds': {'pretermination': 300, 'gateway': 90, 'shared_instance': 300, 'shared_disks': 240},
            'interface_endpoints': 0, 'internet_gateways': 1, 'queue_count': 1, 'root_gib': 8,
            'instance_type': 't3.nano', 'public_network': True, 'auto_public_ipv4': 1, 'estimated_cost_usd': 0.01})
        self.data['documentation'].append(DOC)
        config = self.setup_public_boundary()
        guest = GUEST.replace('__CONFIG__', repr(config))
        self.data['guest_program'] = guest
        request = self.request()
        request.pop('IamInstanceProfile')
        iid = self.launch_public_guest('launch-without-profile', guest, request)
        self.state(iid, 'running', 'identity-running')
        self.ec2('running-noop-metadata-options', 'modify_instance_metadata_options', {'InstanceId': iid, 'HttpTokens': 'required'}, required=True)
        self.ec2('running-noop-metadata-described', 'describe_instances', {'InstanceIds': [iid]}, required=True)
        initial = self.identity_console(iid, 'without-profile', seconds=180)
        if not initial or not any(row['actor'] == 'intrinsic' and row['action'] == 'GetCallerIdentity' and row['status'] == 200 for row in initial.get('signed', [])):
            raise RuntimeError('No signed intrinsic identity observation')
        self.ec2('attach-owned-profile', 'associate_iam_instance_profile', {'InstanceId': iid, 'IamInstanceProfile': {'Name': self.data['guest_role']}}, required=True)
        attached = self.identity_console(iid, 'with-profile', seconds=300)
        if not attached: raise RuntimeError('Attached-profile comparison unavailable')
        if not any(row['actor'] == 'profile' and row['service'] == 'sqs' and row['status'] == 200 for row in attached.get('signed', [])):
            raise RuntimeError('Resource-grant positive control unavailable')
        if self.deadline - time.monotonic() >= 240:
            self.ec2('identity-stop', 'stop_instances', {'InstanceIds': [iid]}, required=True)
            self.state(iid, 'stopped', 'identity-stopped')
            self.ec2('stopped-noop-metadata-options', 'modify_instance_metadata_options', {'InstanceId': iid, 'HttpTokens': 'required'}, required=True)
            self.ec2('stopped-noop-metadata-described', 'describe_instances', {'InstanceIds': [iid]}, required=True)
            self.ec2('stopped-effective-metadata-options', 'modify_instance_metadata_options', {'InstanceId': iid, 'InstanceMetadataTags': 'disabled'}, required=True)
            self.ec2('stopped-effective-metadata-described', 'describe_instances', {'InstanceIds': [iid]}, required=True)
            self.ec2('identity-start', 'start_instances', {'InstanceIds': [iid]}, required=True)
            self.state(iid, 'running', 'identity-restarted')
            if not self.identity_console(iid, 'after-start', seconds=150):
                raise RuntimeError('Restarted intrinsic observation unavailable')
        self.data['capture_complete_at'] = now()
        self.data['gaps'].extend(['Single account/region; integrated services other than STS GetCallerIdentity are not exercised.',
            'Key-change observations do not establish a refresh interval or causal link to profile attachment; expiration and prior-key validity across stop/start were not exercised.',
            'No equality or monotonicity contract is inferred between intrinsic info, credential, EC2 launch or audit timestamps.',
            'IMDS v1 and version-dependent credential/policy behavior were not exercised.'])
        self.save()

    def cleanup(self):
        signal.alarm(0)
        self.cleaning = True
        owned = self.data['owned']
        failures = []
        self.discover_owned()
        # Release the auto public address before detaching its gateway. The
        # shared cleanup independently verifies terminated instances and absent
        # ENIs/root disks; an auto address is not an Elastic IP allocation.
        for iid in owned['instances']:
            self.ec2('cleanup-public-terminate-' + iid, 'terminate_instances', {'InstanceIds': [iid]})
        for iid in owned['instances']:
            try: self.state(iid, 'terminated', 'cleanup-public-terminal-' + iid, seconds=300)
            except Exception as error: failures.append({'public_instance': iid, 'error': type(error).__name__})
        if owned.get('route_table'):
            self.ec2('cleanup-public-route-delete', 'delete_route', {'RouteTableId': owned['route_table'], 'DestinationCidrBlock': '0.0.0.0/0'})
            routes = self.ec2('cleanup-public-route-absence', 'describe_route_tables', {'RouteTableIds': [owned['route_table']]})
            if self.data['calls'][-1]['code'] not in ('Success', 'InvalidRouteTableID.NotFound') or any(route.get('GatewayId') == owned.get('internet_gateway') for table in routes.get('RouteTables', []) for route in table['Routes']):
                failures.append('owned gateway route absence unverified')
        if owned.get('internet_gateway'):
            for attempt in range(45):
                self.ec2('cleanup-internet-gateway-detach-' + str(attempt), 'detach_internet_gateway', {'InternetGatewayId': owned['internet_gateway'], 'VpcId': owned['vpc']})
                self.ec2('cleanup-internet-gateway-delete-' + str(attempt), 'delete_internet_gateway', {'InternetGatewayId': owned['internet_gateway']})
                result = self.ec2('cleanup-internet-gateway-absence-' + str(attempt), 'describe_internet_gateways', {'InternetGatewayIds': [owned['internet_gateway']]})
                if self.data['calls'][-1]['code'] == 'InvalidInternetGatewayID.NotFound' or (self.data['calls'][-1]['code'] == 'Success' and not result.get('InternetGateways')): break
                time.sleep(2)
            else: failures.append('owned internet gateway absence unverified')
        if owned.get('queue'):
            self.observe('cleanup-queue-delete', 'sqs', 'delete_queue', {'QueueUrl': owned['queue']})
            self.observe('cleanup-queue-absence', 'sqs', 'get_queue_attributes', {'QueueUrl': owned['queue'], 'AttributeNames': ['QueueArn']})
            if self.data['calls'][-1]['code'] not in ('AWS.SimpleQueueService.NonExistentQueue', 'QueueDoesNotExist'):
                failures.append('queue absence unverified')
        try:
            super().cleanup()
        finally:
            self.data['cleanup']['intrinsic_boundary_absence_verified'] = not failures
            self.data['cleanup']['failures'].extend(failures)
            self.data['cleanup']['complete'] = self.data['cleanup'].get('complete', False) and not failures
            self.save()
        if failures: raise RuntimeError('Intrinsic boundary cleanup incomplete')

    def audit_guest_identity(self):
        request_ids = {}
        labels = {}
        for observation in self.data['guest_observations']:
            guest = observation['guest']
            for call in guest.get('signed', []):
                if call.get('action') == 'GetCallerIdentity' and call.get('status') == 200 and call.get('request_id'):
                    request_id = call['request_id']
                    request_ids[request_id] = {key: call[key] for key in ('actor', 'metadata_version', 'source') if key in call}
                    labels[request_id] = ':'.join(str(value) for value in (
                        'guest', guest.get('observation_id') or guest.get('boot_id') or observation.get('call') or request_id,
                        call.get('actor'), call.get('metadata_version'), call.get('source'), call['action'])
                        if value is not None)
        if not request_ids:
            raise RuntimeError('No successful guest identity requests to correlate')
        audit = None
        try:
            audit = collect_history(
                lambda parameters: self.clients['cloudtrail'].lookup_events(**parameters),
                labels, start_time=self.data['captured_at'], max_pages=4,
                lookup_attributes=({'AttributeKey': 'EventName', 'AttributeValue': 'GetCallerIdentity'},))
        except CollectionError as error:
            audit = error.result
            raise
        finally:
            if audit is not None:
                audit.update(source_fixture=str(self.args.output), captured_at=now(), request_ids=request_ids)
                for row in audit['events']:
                    row.update(request_ids.get(row['event'].get('requestID'), {}))
                for page in audit['pages']:
                    page['request_id'] = page.get('response_metadata', {}).get('RequestId')
                path = self.args.output.with_name(self.args.output.stem + '_audit.json')
                path.write_text(json.dumps(safe(audit), indent=2) + '\n')
        print(json.dumps({'audit_events': len(audit['events']), 'missing': len(audit['missing_request_ids'])}), flush=True)


def run_identity_capture(capture_type: type[IdentityCapture], output: str, description: str) -> None:
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument('--account', required=True)
    parser.add_argument('--region', choices=['us-east-1'], default='us-east-1')
    parser.add_argument('--output', type=Path, default=Path(output))
    parser.add_argument('--cleanup-only', action='store_true')
    parser.add_argument('--audit-only', action='store_true')
    parser.add_argument('--live-seconds', type=int, choices=range(300, 901), default=900)
    args = parser.parse_args()
    capture = capture_type(args)
    if args.audit_only:
        capture.audit_guest_identity()
        return
    for signum in (signal.SIGALRM, signal.SIGINT, signal.SIGTERM): signal.signal(signum, interrupt)
    try:
        if not args.cleanup_only: capture.run()
    except Exception as error:
        capture.data['failure'] = {'type': type(error).__name__, 'message': str(error), 'at': now()}
        capture.save()
        raise
    finally:
        try: capture.cleanup()
        finally: capture.handoff()


if __name__ == '__main__':
    run_identity_capture(IdentityCapture, '.stackd/probes/ec2/instance_identity_credentials.json', __doc__)
