#!/usr/bin/env python3
"""Read-only impersonation calibration against one explicitly owned native cluster."""
import argparse
import base64
import json
import pathlib
import ssl
import subprocess
import urllib.error
import urllib.request


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--account', required=True)
    parser.add_argument('--cluster-evidence', required=True)
    parser.add_argument('--evidence', required=True)
    args = parser.parse_args()
    evidence = json.loads(pathlib.Path(args.cluster_evidence).read_text())
    cluster = evidence['cluster']
    if cluster['name'] != evidence['prefix'] or not cluster['name'].startswith('stackd-eks-depth-'):
        raise RuntimeError('exact-owned native cluster evidence required')
    identity = subprocess.run(['aws', 'sts', 'get-caller-identity', '--region', evidence['region'], '--output', 'json'], capture_output=True, text=True, check=True)
    if json.loads(identity.stdout)['Account'] != args.account or cluster['arn'].split(':')[4] != args.account:
        raise RuntimeError('native caller and cluster must match --account')
    auth = subprocess.run(['aws', 'eks', 'get-token', '--cluster-name', cluster['name'], '--region', evidence['region']], capture_output=True, text=True, check=True)
    token = json.loads(auth.stdout)['status']['token']
    context = ssl.create_default_context(cadata=base64.b64decode(cluster['certificateAuthority']['data']).decode())
    observed = {'cluster': cluster['name'], 'observations': []}
    for label, path, body, extra in [
        ('originalCaller', '/apis/authentication.k8s.io/v1/selfsubjectreviews', {'apiVersion': 'authentication.k8s.io/v1', 'kind': 'SelfSubjectReview', 'spec': {}}, {}),
        ('policyAdminImpersonatesUnknownUser', '/api/v1/namespaces', None, {'Impersonate-User': 'stackd-native-impersonation-target'}),
    ]:
        headers = {'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json', **extra}
        request = urllib.request.Request(cluster['endpoint'] + path, data=json.dumps(body).encode() if body is not None else None, headers=headers)
        try:
            with urllib.request.urlopen(request, context=context, timeout=30) as response:
                status, result = response.status, json.load(response)
        except urllib.error.HTTPError as error:
            status, result = error.code, json.load(error)
        observed['observations'].append({'label': label, 'status': status, 'response': result})
    pathlib.Path(args.evidence).write_text(json.dumps(observed, indent=2) + '\n')
    print(json.dumps({'cluster': cluster['name'], 'observations': [(row['label'], row['status']) for row in observed['observations']]}))


if __name__ == '__main__':
    main()
