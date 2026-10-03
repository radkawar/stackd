"""Exact-owned pod association and official agent image native capture extension."""
import base64
import json
import pathlib
import ssl
import subprocess
import time
import urllib.request
import uuid


def capture(aws, record, clusterName, subnetIDs, until):
    del subnetIDs
    prefix = 'stackd-podidentity-' + uuid.uuid4().hex[:12]
    roles = []
    associations = []
    addon = False
    evidence = {'cluster': clusterName, 'observations': [], 'cleanup': []}
    output = pathlib.Path(__file__).resolve().parents[1] / '.stackd/probes/eks/podidentity_native_agent.json'

    def save():
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(evidence, indent=2) + '\n')

    def call(operation, **values):
        try:
            response = record('eks', operation, **values)
            if operation == 'create-pod-identity-association':
                association = response['association']['associationId']
                if association not in associations:
                    associations.append(association)
            if operation == 'delete-pod-identity-association' and values['associationId'] in associations:
                associations.remove(values['associationId'])
            return response
        except RuntimeError as error:
            evidence['observations'].append({'operation': operation, 'input': values, 'error': str(error)})
            save()
            return None

    def clean(label, fn):
        try:
            fn()
            evidence['cleanup'].append({'operation': label, 'ok': True})
        except Exception as error:
            evidence['cleanup'].append({'operation': label, 'error': str(error)})
        save()

    try:
        trust = {'Version': '2012-10-17', 'Statement': [{'Effect': 'Allow', 'Principal': {'Service': 'pods.eks.amazonaws.com'}, 'Action': ['sts:AssumeRole', 'sts:TagSession']}]}
        role = record('iam', 'create-role', RoleName=prefix, AssumeRolePolicyDocument=json.dumps(trust))['Role']['Arn']
        roles.append(prefix)
        time.sleep(10)
        values = dict(clusterName=clusterName, namespace='capture-absent', serviceAccount='capture-sa', roleArn=role, clientRequestToken=str(uuid.uuid4()))
        first = call('create-pod-identity-association', **values)
        if first is None:
            raise RuntimeError('Native association creation failed')
        association = first['association']['associationId']
        call('create-pod-identity-association', **dict(values, disableSessionTags=True))
        update_token = str(uuid.uuid4())
        call('update-pod-identity-association', clusterName=clusterName, associationId=association, clientRequestToken=update_token, disableSessionTags=True)
        call('update-pod-identity-association', clusterName=clusterName, associationId=association, clientRequestToken=update_token, disableSessionTags=False)
        call('describe-pod-identity-association', clusterName=clusterName, associationId=association)
        call('create-pod-identity-association', **dict(values, serviceAccount='other-sa', clientRequestToken='short'))
        call('delete-pod-identity-association', clusterName=clusterName, associationId=association)
        call('delete-pod-identity-association', clusterName=clusterName, associationId=association)
        record('eks', 'create-addon', clusterName=clusterName, addonName='eks-pod-identity-agent', resolveConflicts='OVERWRITE')
        addon = True
        status = until(lambda: (lambda value: value if value['status'] not in ['CREATING', 'UPDATING'] else None)(aws('eks', 'describe-addon', clusterName=clusterName, addonName='eks-pod-identity-agent')['addon']), 900)
        evidence['addon'] = status
        cluster = aws('eks', 'describe-cluster', name=clusterName)['cluster']
        region = cluster['arn'].split(':')[3]
        token = json.loads(subprocess.check_output(['aws', 'eks', 'get-token', '--cluster-name', clusterName, '--region', region, '--output', 'json']))['status']['token']
        request = urllib.request.Request(cluster['endpoint'] + '/apis/apps/v1/namespaces/kube-system/daemonsets/eks-pod-identity-agent', headers={'Authorization': 'Bearer ' + token})
        tls = ssl.create_default_context(cadata=base64.b64decode(cluster['certificateAuthority']['data']).decode())
        with urllib.request.urlopen(request, context=tls, timeout=30) as response:
            evidence['daemonSet'] = json.load(response)
        save()
    finally:
        if addon:
            clean('delete-addon', lambda: aws('eks', 'delete-addon', clusterName=clusterName, addonName='eks-pod-identity-agent'))
        for association in associations:
            clean('delete-pod-identity-association', lambda association=association: aws('eks', 'delete-pod-identity-association', clusterName=clusterName, associationId=association))
        for name in roles:
            clean('delete-role', lambda name=name: aws('iam', 'delete-role', RoleName=name))
