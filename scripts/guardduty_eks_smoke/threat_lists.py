#!/usr/bin/env python3
"""Owned real Kubernetes audit -> active S3 threat lists -> signed GuardDuty SDK.

Uses the existing EKS smoke's isolated controller, real k3d and exact cleanup.
A loopback native API request carries X-Forwarded-For to exercise public IPv4
matching against the source recorded by Kubernetes itself. This proves processing
of native audit origin metadata, not Internet-origin attribution or AWS detection.
No audit frames, journal rows or findings are injected.
"""
import argparse
import base64
import ipaddress
import json
from pathlib import Path
import sqlite3
import ssl
import urllib.error
import urllib.parse
import urllib.request
import uuid

import boto3
from botocore.config import Config
from main import Smoke, REGION, require


class ThreatSmoke(Smoke):
    def __init__(self, args):
        super().__init__(args)
        self.clients['s3'] = boto3.client('s3', endpoint_url=self.endpoint, region_name=REGION,
            aws_access_key_id='test', aws_secret_access_key='test',
            config=Config(signature_version='s3v4', s3={'addressing_style': 'path'},
                          retries={'total_max_attempts': 1}, ignore_configured_endpoint_urls=True))
        self.bucket = None
        self.rows = {}
        self.evidence['scope'] = __doc__

    def request(self, method, resource, name='', source='8.8.8.8', denied=False):
        marker = 'threat-' + uuid.uuid4().hex
        path = f'/api/v1/namespaces/{self.prefix}/{resource}' + ('/' + name if name else '')
        path += '?fieldManager=' + marker
        headers = {'X-Forwarded-For': source, 'User-Agent': 'stackd-guardduty-threat-smoke',
                   'Content-Type': 'application/json'}
        if denied:
            headers['Impersonate-User'] = self.prefix + '-unprivileged'
            headers['Impersonate-Group'] = 'system:authenticated'
        request = urllib.request.Request(self.native_endpoint + path, method=method, headers=headers,
                                         data=b'{}' if method == 'DELETE' else None)
        try:
            with self.opener.open(request, timeout=30) as response:
                status = response.status
                response.read()
        except urllib.error.HTTPError as error:
            status = error.code
            error.close()
        require(status == (403 if denied else 200), {'path': path, 'status': status})
        audit = self.completed_audit(marker)
        require(audit['sourceIPs'][0] == source and audit['responseStatus']['code'] == status, audit)
        def admitted():
            with sqlite3.connect((self.root / 'state.db').as_uri() + '?mode=ro', uri=True) as db:
                return db.execute('SELECT sequence FROM kubernetes_audit_events WHERE cluster_id=? AND audit_id=? AND stage=?',
                                  (self.native_id, audit['auditID'], 'ResponseComplete')).fetchone()
        self.wait('transactional source admission', admitted)
        return audit

    def list_state(self, threat, active):
        kind, key, identifier = ('threat_intel_set', 'ThreatIntelSetId', self.threat) if threat else ('ip_set', 'IpSetId', self.trusted)
        self.call('guardduty', 'update_' + kind, DetectorId=self.detector, **{key: identifier}, Activate=active)
        self.wait('list application', lambda: self.call('guardduty', 'get_' + kind,
            DetectorId=self.detector, **{key: identifier})['Status'] == ('ACTIVE' if active else 'INACTIVE'))

    def positive(self, label, tactic, method, resource, name='', denied=False, count=1):
        audit = self.request(method, resource, name, denied=denied)
        kind = tactic + ':Kubernetes/MaliciousIPCaller.Custom'
        matches = [row for row in self.findings() if row['Type'] == kind and
                   row['Service']['Action']['KubernetesApiCallAction']['RequestUri'] == audit['requestURI']]
        require(len(matches) == 1, {'audit': audit, 'findings': self.findings()})
        finding = matches[0]
        require(finding['Service']['Count'] == count, finding)
        require(finding['Service']['Evidence']['ThreatIntelligenceDetails'] == [{'ThreatListName': 'owned-native-threat'}], finding)
        require(finding['Service']['Action']['KubernetesApiCallAction']['SourceIps'] == [audit['sourceIPs'][0]], finding)
        self.rows[finding['Id']] = {'audit': audit, 'finding': finding}
        self.evidence['observations'][label] = self.rows[finding['Id']]
        self.save()

    def negative(self, label, **kwargs):
        before = self.snapshot()
        audit = self.request('GET', 'secrets', 'dummy-secret', **kwargs)
        require(self.snapshot() == before, {'label': label, 'audit': audit, 'findings': self.snapshot()})
        self.evidence['observations'][label] = {'audit': audit, 'unchanged': True}
        self.save()

    def sdk(self):
        expected = []
        for row in self.rows.values():
            a, f = row['audit'], row['finding']
            user, obj = a.get('impersonatedUser', a['user']), a['objectRef']
            want = {'ID': f['Id'], 'Type': f['Type'], 'Count': f['Service']['Count'],
                    'Username': user['username'], 'Groups': user.get('groups', []),
                    'URI': a['requestURI'], 'Verb': a['verb'], 'Status': a['responseStatus']['code'],
                    'Namespace': obj.get('namespace', ''), 'Resource': obj.get('resource', ''),
                    'Name': obj.get('name', ''), 'Subresource': obj.get('subresource', ''),
                    'SourceIPs': [a['sourceIPs'][0]], 'UserAgent': a['userAgent'],
                    'ThreatLists': ['owned-native-threat']}
            if a['verb'] == 'delete':
                want['DeleteOptions'] = {'observed': True, 'dryRun': False}
            expected.append(want)
        result = self.command(['go', 'run', './scripts/guardduty_eks_smoke/sdk', '-custom-threats',
            '-endpoint', self.endpoint, '-account', self.account, '-region', REGION,
            '-detector', self.detector, '-cluster-arn', self.cluster['arn'], '-cluster-name', self.prefix],
            stdin=json.dumps(expected), timeout=300, cwd=Path(__file__).resolve().parents[2])
        return json.loads(result)

    def run(self):
        self.setup()
        configuration = json.loads(self.kube('config', 'view', '--raw', '--minify', '-o', 'json', native=True))
        cluster, user = configuration['clusters'][0]['cluster'], configuration['users'][0]['user']
        self.native_endpoint = cluster['server']
        parsed = urllib.parse.urlsplit(self.native_endpoint)
        require(parsed.scheme == 'https' and ipaddress.ip_address(parsed.hostname).is_loopback, 'native endpoint must be loopback')
        context = ssl.create_default_context(cadata=base64.b64decode(cluster['certificate-authority-data']).decode())
        cert, key = self.root / 'client.crt', self.root / 'client.key'
        cert.write_bytes(base64.b64decode(user['client-certificate-data']))
        key.write_bytes(base64.b64decode(user['client-key-data']))
        key.chmod(0o600)
        context.load_cert_chain(cert, key)
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=context))
        self.kube('create', 'secret', 'generic', 'dummy-secret', '-n', self.prefix, '--from-literal=proof=owned', native=True)
        self.kube('create', 'configmap', 'delete-proof', '-n', self.prefix, '--from-literal=proof=owned', native=True)
        self.negative('before-list')
        self.call('s3', 'create_bucket', Bucket=self.prefix)
        self.bucket = self.prefix
        self.call('s3', 'put_object', Bucket=self.bucket, Key='list.txt', Body=b'8.8.8.8/32\n')
        location = f'https://s3.{REGION}.amazonaws.com/{self.bucket}/list.txt'
        self.threat = self.call('guardduty', 'create_threat_intel_set', DetectorId=self.detector,
            Name='owned-native-threat', Location=location, Format='TXT', Activate=True)['ThreatIntelSetId']
        self.wait('active threat list', lambda: self.call('guardduty', 'get_threat_intel_set',
            DetectorId=self.detector, ThreatIntelSetId=self.threat)['Status'] == 'ACTIVE')
        self.positive('credential-read', 'CredentialAccess', 'GET', 'secrets', 'dummy-secret')
        self.positive('denied-credential-read', 'CredentialAccess', 'GET', 'secrets', 'forbidden', denied=True)
        self.positive('discovery', 'Discovery', 'GET', 'pods')
        self.positive('deletion', 'Impact', 'DELETE', 'configmaps', 'delete-proof')
        require(not self.kube('get', 'configmap', 'delete-proof', '-n', self.prefix, '--ignore-not-found', '-o', 'json', native=True).strip(), 'deleted configmap survived')
        self.negative('unmatched-public-source', source='1.1.1.1')
        self.negative('private-source', source='10.0.0.1')
        self.trusted = self.call('guardduty', 'create_ip_set', DetectorId=self.detector,
            Name='owned-native-trusted', Location=location, Format='TXT', Activate=True)['IpSetId']
        self.wait('active trusted list', lambda: self.call('guardduty', 'get_ip_set',
            DetectorId=self.detector, IpSetId=self.trusted)['Status'] == 'ACTIVE')
        self.negative('trusted-precedence')
        before = self.snapshot()
        self.stop(); self.start()
        require(self.snapshot() == before, 'restart changed native finding evidence/counts')
        self.negative('trusted-after-restart')
        self.list_state(False, False)
        self.positive('trust-deactivated', 'CredentialAccess', 'GET', 'secrets', 'dummy-secret', count=2)
        self.list_state(True, False)
        self.negative('threat-deactivated')
        self.list_state(True, True)
        self.positive('threat-reactivated', 'CredentialAccess', 'GET', 'secrets', 'dummy-secret', count=3)
        self.evidence['observations']['goSDK'] = self.sdk()
        self.evidence['observations']['cloudWatchAfter'] = self.no_cloudwatch()
        self.evidence['passed'] = True
        self.save()

    def cleanup(self):
        errors = []
        if self.bucket:
            try:
                self.call('s3', 'delete_object', Bucket=self.bucket, Key='list.txt')
                self.call('s3', 'delete_bucket', Bucket=self.bucket)
                self.evidence['cleanup'].append({'action': 'delete owned list object and bucket', 'ok': True})
            except Exception as error:
                errors.append(str(error))
                self.evidence['passed'] = False
                self.evidence['cleanup'].append({'action': 'delete owned list object and bucket', 'error': str(error)})
        return errors + super().cleanup()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--k3d', type=Path, required=True)
    parser.add_argument('--evidence', type=Path, required=True)
    parser.add_argument('--docker-host', default='unix:///var/run/docker.sock')
    parser.add_argument('--image', default='busybox:1.37.0')
    args = parser.parse_args()
    args.binary = args.binary.resolve(strict=True)
    args.k3d = args.k3d.resolve(strict=True)
    smoke = ThreatSmoke(args)
    try:
        smoke.run()
    except BaseException as error:
        smoke.evidence['passed'] = False
        smoke.evidence['failure'] = str(error)
        smoke.save()
        raise
    finally:
        errors = smoke.cleanup()
    require(not errors, errors)
    print(json.dumps({'passed': True, 'evidence': str(args.evidence)}))


if __name__ == '__main__':
    main()
