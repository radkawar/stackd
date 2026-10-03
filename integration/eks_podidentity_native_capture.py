#!/usr/bin/env python3
"""Native association contract capture on an explicitly exact-owned EKS cluster."""
import argparse
import json
import pathlib
import subprocess
import time
import uuid


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--cluster', required=True)
    parser.add_argument('--account', required=True)
    parser.add_argument('--region', default='us-east-1')
    parser.add_argument('--evidence', required=True)
    args = parser.parse_args()
    result = {'cluster': args.cluster, 'region': args.region, 'calls': [], 'cleanup': []}
    path = pathlib.Path(args.evidence)
    associations = []
    role_name = 'stackd-podidentity-' + uuid.uuid4().hex[:12]
    role_created = False

    def save():
        path.write_text(json.dumps(result, indent=2) + '\n')

    def aws(service, operation, **values):
        process = subprocess.run(['aws', service, operation, '--region', args.region, '--output', 'json', '--cli-input-json', json.dumps(values)], text=True, capture_output=True, timeout=60)
        if process.returncode:
            raise RuntimeError(process.stderr.strip())
        return json.loads(process.stdout) if process.stdout.strip() else {}

    def capture(operation, **values):
        call = {'operation': operation, 'input': values}
        result['calls'].append(call)
        try:
            response = aws('eks', operation, **values)
            call['output'] = response
            if operation == 'create-pod-identity-association':
                association = response['association']['associationId']
                if association not in associations:
                    associations.append(association)
            elif operation == 'delete-pod-identity-association':
                association = values['associationId']
                if association in associations:
                    associations.remove(association)
            return response
        except RuntimeError as error:
            call['error'] = str(error)
            return None
        finally:
            save()

    def cleanup(operation, fn):
        try:
            fn()
            result['cleanup'].append({'operation': operation, 'ok': True})
        except Exception as error:
            result['cleanup'].append({'operation': operation, 'error': str(error)})
        save()

    try:
        identity = aws('sts', 'get-caller-identity')
        if identity['Account'] != args.account:
            raise RuntimeError('Native account mismatch')
        deadline = time.monotonic() + 1500
        while True:
            cluster = aws('eks', 'describe-cluster', name=args.cluster)['cluster']
            if cluster.get('tags', {}).get('stackd-capture') != args.cluster:
                raise RuntimeError('Refusing a cluster without the exact capture ownership tag')
            if cluster['status'] == 'ACTIVE':
                break
            if cluster['status'] != 'CREATING' or time.monotonic() > deadline:
                raise RuntimeError('Native cluster did not become ACTIVE')
            time.sleep(10)
        trust = {'Version': '2012-10-17', 'Statement': [{'Effect': 'Allow', 'Principal': {'Service': 'pods.eks.amazonaws.com'}, 'Action': ['sts:AssumeRole', 'sts:TagSession']}]}
        role = aws('iam', 'create-role', RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))['Role']['Arn']
        role_created = True
        time.sleep(10)
        values = {'clusterName': args.cluster, 'namespace': 'capture-absent', 'serviceAccount': 'capture-sa', 'roleArn': role, 'clientRequestToken': str(uuid.uuid4()), 'tags': {'capture': role_name}}
        first = capture('create-pod-identity-association', **values)
        if first is None:
            raise RuntimeError('Initial native association was rejected')
        association = first['association']['associationId']
        capture('create-pod-identity-association', **values)
        capture('create-pod-identity-association', **dict(values, roleArn=role, disableSessionTags=True))
        capture('create-pod-identity-association', **dict(values, clientRequestToken=str(uuid.uuid4())))
        capture('describe-pod-identity-association', clusterName=args.cluster, associationId=association)
        capture('update-pod-identity-association', clusterName=args.cluster, associationId=association, disableSessionTags=True, targetRoleArn=role)
        capture('describe-pod-identity-association', clusterName=args.cluster, associationId=association)
        capture('update-pod-identity-association', clusterName=args.cluster, associationId=association, targetRoleArn='')
        capture('list-pod-identity-associations', clusterName=args.cluster, namespace='capture-absent', serviceAccount='capture-sa', maxResults=1)
        capture('create-pod-identity-association', **dict(values, clientRequestToken=str(uuid.uuid4()), namespace='Invalid_Namespace'))
        capture('delete-pod-identity-association', clusterName=args.cluster, associationId=association)
        # Confirm deletion before releasing cleanup ownership; eventual visibility
        # remains an observation rather than a fabricated state transition.
        capture('describe-pod-identity-association', clusterName=args.cluster, associationId=association)
    except Exception as error:
        result['failure'] = str(error)
        save()
        raise
    finally:
        for association in associations:
            cleanup('delete-pod-identity-association', lambda association=association: aws('eks', 'delete-pod-identity-association', clusterName=args.cluster, associationId=association))
        if role_created:
            cleanup('delete-role', lambda: aws('iam', 'delete-role', RoleName=role_name))
    print(json.dumps({'fixture': str(path), 'calls': len(result['calls']), 'cleanup': result['cleanup']}))


if __name__ == '__main__':
    main()
