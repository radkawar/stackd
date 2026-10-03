"""Native IRSA extension for eks_native_capture.py; no nodes or workload execution."""
import base64
import copy
import hashlib
import json
import pathlib
import re
import ssl
import subprocess
import time
import urllib.error
import urllib.request


ROOT = pathlib.Path(__file__).resolve().parents[1]


def token_description(token):
    header, payload, _ = token.split('.')
    decode = lambda part: json.loads(base64.urlsafe_b64decode(part + '=' * (-len(part) % 4)))
    return {'sha256': hashlib.sha256(token.encode()).hexdigest(),
            'header': decode(header), 'claims': decode(payload)}


def capture(aws, record, prefix, subnets, until):
    del subnets
    inputs = json.loads((ROOT / 'testdata/aws/eks/irsa_inputs.json').read_text())
    output = ROOT / '.stackd/probes/eks/irsa_native.json'
    namespace = prefix + '-irsa'
    owned = {'roles': [], 'associations': [], 'serviceAccounts': [], 'pods': []}
    evidence = {'clusterName': prefix, 'namespace': namespace, 'startedAt': time.time(),
                'inputFixture': 'testdata/aws/eks/irsa_inputs.json', 'sources': inputs['sources'],
                'limits': ['No scheduled workload was executed; no nodes were created.',
                           'TokenRequest probes use real EKS-signed JWTs bound to real unscheduled Pods.',
                           'STS probes run on the capture host, not in Pods.',
                           'No Pod Identity agent execution or seven-day signing-key rotation was captured.'],
                'observations': [], 'cleanup': []}

    def save():
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(evidence, indent=2) + '\n')

    def observe(row):
        evidence['observations'].append(row)
        save()
        return row

    def api(service, operation, **values):
        started = time.time()
        try:
            result = record(service, operation, **values)
        except Exception as error:
            observe({'service': service, 'operation': operation, 'input': values,
                     'at': started, 'error': str(error)})
            raise
        observe({'service': service, 'operation': operation, 'input': values,
                 'at': started, 'output': result})
        return result

    def clean(label, fn):
        try:
            result = fn()
            evidence['cleanup'].append({'operation': label, 'ok': True, 'output': result})
        except Exception as error:
            evidence['cleanup'].append({'operation': label, 'error': str(error)})
        save()

    try:
        expected_account = aws('sts', 'get-caller-identity')['Account']
        cluster = api('eks', 'describe-cluster', name=prefix)['cluster']
        region = cluster['arn'].split(':')[3]
        account = cluster['arn'].split(':')[4]
        if account != expected_account or region != 'us-east-1' or not prefix.startswith('stackd-eks-depth-'):
            raise RuntimeError('exact-owned authorized native cluster required')
        evidence['cluster'] = cluster
        issuer = cluster['identity']['oidc']['issuer']
        for suffix in ['/.well-known/openid-configuration', '/keys']:
            url = issuer + suffix
            # HEAD 403 is retained in irsa_native_failed_head.json; do not repeat it merely to confirm.
            for method in ['GET']:
                started = time.time()
                request = urllib.request.Request(url, method=method)
                try:
                    with urllib.request.urlopen(request, timeout=30) as response:
                        body = response.read()
                        observe({'service': 'oidc', 'operation': method, 'url': url, 'at': started,
                                 'status': response.status, 'headers': dict(response.headers),
                                 'output': json.loads(body) if body else None})
                except urllib.error.HTTPError as error:
                    observe({'service': 'oidc', 'operation': method, 'url': url, 'at': started,
                             'status': error.code, 'headers': dict(error.headers),
                             'error': error.read().decode(), 'reason': str(error)})
        provider = api('iam', 'create-open-id-connect-provider', Url=issuer,
                       ClientIDList=['sts.amazonaws.com'], Tags=[{'Key': 'stackd-capture', 'Value': prefix}])['OpenIDConnectProviderArn']
        owned['provider'] = provider
        evidence['provider'] = api('iam', 'get-open-id-connect-provider', OpenIDConnectProviderArn=provider)
        condition_key = issuer.removeprefix('https://')
        trust = {'Version': '2012-10-17', 'Statement': [{'Effect': 'Allow',
                 'Principal': {'Federated': provider}, 'Action': 'sts:AssumeRoleWithWebIdentity',
                 'Condition': {'StringEquals': {condition_key + ':sub': 'system:serviceaccount:' + namespace + ':defaults',
                                               condition_key + ':aud': 'sts.amazonaws.com'}}}]}
        role_name = prefix + '-irsa'
        role = api('iam', 'create-role', RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))['Role']['Arn']
        owned['roles'].append(role_name)
        pi_name = prefix + '-pi'
        pi_trust = {'Version': '2012-10-17', 'Statement': [{'Effect': 'Allow',
                    'Principal': {'Service': 'pods.eks.amazonaws.com'},
                    'Action': ['sts:AssumeRole', 'sts:TagSession']}]}
        pi_role = api('iam', 'create-role', RoleName=pi_name, AssumeRolePolicyDocument=json.dumps(pi_trust))['Role']['Arn']
        owned['roles'].append(pi_name)
        auth = subprocess.run(['aws', 'eks', 'get-token', '--cluster-name', prefix, '--region', region,
                               '--output', 'json'], capture_output=True, text=True, check=True)
        token = json.loads(auth.stdout)['status']['token']
        tls = ssl.create_default_context(cadata=base64.b64decode(cluster['certificateAuthority']['data']).decode())

        def kube(label, method, path, body=None, required=True):
            started = time.time()
            request = urllib.request.Request(cluster['endpoint'] + path, method=method,
                      data=json.dumps(body).encode() if body is not None else None,
                      headers={'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json'})
            try:
                with urllib.request.urlopen(request, context=tls, timeout=45) as response:
                    status, result = response.status, json.load(response)
            except urllib.error.HTTPError as error:
                status, result = error.code, json.load(error)
            safe = copy.deepcopy(result)
            if isinstance(safe.get('status'), dict) and safe['status'].get('token'):
                raw_token = safe['status'].pop('token')
                safe['status']['tokenDescription'] = token_description(raw_token)
            observe({'service': 'kubernetes', 'label': label, 'operation': method, 'path': path,
                     'input': body, 'at': started, 'status': status, 'output': safe})
            if required and status >= 400:
                raise RuntimeError(label + ': ' + str(status) + ': ' + json.dumps(safe))
            return status, result

        kube('create-namespace', 'POST', '/api/v1/namespaces',
             {'apiVersion': 'v1', 'kind': 'Namespace', 'metadata': {'name': namespace}})
        owned['namespace'] = True
        base = '/api/v1/namespaces/' + namespace
        admitted = {}
        for case in inputs['cases']:
            name = case['name']
            annotations = {'eks.amazonaws.com/' + k: v for k, v in case.get('serviceAccountAnnotations', {}).items()}
            if case.get('annotated', True):
                annotations['eks.amazonaws.com/role-arn'] = role
            sa = {'apiVersion': 'v1', 'kind': 'ServiceAccount',
                  'metadata': {'name': name, 'namespace': namespace, 'annotations': annotations},
                  **case.get('serviceAccountSpec', {})}
            kube(name + '-serviceaccount', 'POST', base + '/serviceaccounts', sa)
            owned['serviceAccounts'].append(name)
            if case.get('association'):
                association = api('eks', 'create-pod-identity-association', clusterName=prefix,
                                  namespace=namespace, serviceAccount=name, roleArn=pi_role)['association']['associationId']
                owned['associations'].append(association)
                api('eks', 'describe-pod-identity-association', clusterName=prefix, associationId=association)
            pod = {'apiVersion': 'v1', 'kind': 'Pod',
                   'metadata': {'name': name, 'namespace': namespace,
                                'annotations': {'eks.amazonaws.com/' + k: v for k, v in case.get('podAnnotations', {}).items()}},
                   'spec': {'serviceAccountName': name, 'restartPolicy': 'Never',
                            'containers': [{'name': 'main', 'image': 'registry.k8s.io/pause:3.10'}],
                            **copy.deepcopy(case.get('podSpec', {}))}}
            status, result = kube(name, 'POST', base + '/pods', pod, required=False)
            if status < 400:
                admitted[name] = result
                owned['pods'].append(name)
            if case.get('association') and status < 400:
                # Observe propagation explicitly; keep every admitted Pod and the delay.
                for attempt in range(1, 7):
                    env_names = {item['name'] for c in result['spec']['containers'] for item in c.get('env', [])}
                    if 'AWS_CONTAINER_CREDENTIALS_FULL_URI' in env_names:
                        break
                    observe({'label': name + '-association-propagation-wait', 'seconds': 15, 'attempt': attempt})
                    time.sleep(15)
                    pod['metadata']['name'] = name + '-propagation-' + str(attempt)
                    status, result = kube(pod['metadata']['name'], 'POST', base + '/pods', pod, required=False)
                    if status >= 400:
                        break
                    owned['pods'].append(pod['metadata']['name'])
                print(json.dumps({'IRSA_ASSOCIATION_OBSERVED': name, 'pod': result}), flush=True)

        kube('unscheduled-pods', 'GET', base + '/pods')
        tokens = {}

        def sts(label, jwt):
            row = {'service': 'sts', 'operation': 'assume-role-with-web-identity', 'label': label,
                   'at': time.time(), 'input': {'RoleArn': role, 'RoleSessionName': 'irsa-native-' + label,
                   'DurationSeconds': 900, 'WebIdentityToken': token_description(jwt)}}
            try:
                result = aws('sts', 'assume-role-with-web-identity', RoleArn=role,
                             RoleSessionName='irsa-native-' + label, DurationSeconds=900, WebIdentityToken=jwt)
                credentials = result.pop('Credentials', {})
                result['Credentials'] = {'Expiration': credentials.get('Expiration'),
                                         'redacted': ['AccessKeyId', 'SecretAccessKey', 'SessionToken']}
                row['output'] = result
            except Exception as error:
                row['error'] = str(error).replace(jwt, '[REDACTED JWT]')
                code = re.search(r'An error occurred \(([^)]+)\)', row['error'])
                row['errorCode'] = code.group(1) if code else None
            observe(row)
            return row

        for case in inputs['stsCases']:
            name = case['name']
            if 'source' in case:
                parts = tokens[case['source']].split('.')
                if case['mutation'] == 'signature':
                    signature = bytearray(base64.urlsafe_b64decode(parts[2] + '=' * (-len(parts[2]) % 4)))
                    signature[0] ^= 1
                    parts[2] = base64.urlsafe_b64encode(signature).decode().rstrip('=')
                else:
                    payload = token_description(tokens[case['source']])['claims']
                    payload['sub'] += '-tampered'
                    parts[1] = base64.urlsafe_b64encode(json.dumps(payload, separators=(',', ':')).encode()).decode().rstrip('=')
                jwt = '.'.join(parts)
            else:
                sa_name = case['serviceAccount']
                pod = admitted[sa_name]
                body = {'apiVersion': 'authentication.k8s.io/v1', 'kind': 'TokenRequest',
                        'spec': {'audiences': [case['audience']], 'expirationSeconds': 900,
                                 'boundObjectRef': {'apiVersion': 'v1', 'kind': 'Pod',
                                                    'name': pod['metadata']['name'], 'uid': pod['metadata']['uid']}}}
                _, response = kube(name + '-token', 'POST', base + '/serviceaccounts/' + sa_name + '/token', body)
                jwt = response['status']['token']
            tokens[name] = jwt
            result = sts(name, jwt)
            if name == 'correct-subject' and 'error' in result:
                # This is a recorded propagation experiment, not a hidden retry.
                for attempt in range(1, 5):
                    observe({'label': 'iam-propagation-wait', 'seconds': 15, 'attempt': attempt})
                    time.sleep(15)
                    result = sts('correct-subject-propagation-' + str(attempt), jwt)
                    if 'error' not in result:
                        break
        kube('delete-token-bound-pod', 'DELETE', base + '/pods/defaults',
             {'apiVersion': 'v1', 'kind': 'DeleteOptions', 'gracePeriodSeconds': 0})
        owned['pods'].remove('defaults')
        absent, _ = kube('bound-pod-absent', 'GET', base + '/pods/defaults', required=False)
        if absent != 404:
            raise RuntimeError('token-bound Pod deletion not yet observed')
        sts('same-token-after-pod-deletion', tokens['correct-subject'])
        evidence['completedAt'] = time.time()
        save()
    except Exception as error:
        evidence['failure'] = str(error)
        save()
        raise
    finally:
        if owned.get('namespace'):
            for name in owned['pods']:
                clean('delete-pod ' + name, lambda name=name: kube('cleanup-pod-' + name, 'DELETE', base + '/pods/' + name,
                      {'apiVersion': 'v1', 'kind': 'DeleteOptions', 'gracePeriodSeconds': 0})[0])
            for name in owned['serviceAccounts']:
                clean('delete-serviceaccount ' + name, lambda name=name: kube('cleanup-sa-' + name, 'DELETE', base + '/serviceaccounts/' + name)[0])
            clean('delete-namespace', lambda: kube('cleanup-namespace', 'DELETE', '/api/v1/namespaces/' + namespace)[0])
            def namespace_absent():
                status, _ = kube('cleanup-namespace-absent', 'GET', '/api/v1/namespaces/' + namespace, required=False)
                return status == 404
            clean('wait-namespace-absent', lambda: until(namespace_absent, 180))
        def aws_absent(service, operation, error_code, **values):
            try:
                result = aws(service, operation, **values)
            except RuntimeError as error:
                if '(' + error_code + ')' not in str(error):
                    raise
                return {'service': service, 'operation': operation, 'input': values,
                        'errorCode': error_code, 'error': str(error)}
            raise RuntimeError('resource still present: ' + json.dumps(result))
        for association in owned['associations']:
            clean('delete-association ' + association, lambda association=association: api('eks', 'delete-pod-identity-association', clusterName=prefix, associationId=association))
            clean('verify-association-absent ' + association, lambda association=association:
                  aws_absent('eks', 'describe-pod-identity-association', 'ResourceNotFoundException',
                             clusterName=prefix, associationId=association))
        for name in owned['roles']:
            clean('delete-role ' + name, lambda name=name: api('iam', 'delete-role', RoleName=name))
            clean('verify-role-absent ' + name, lambda name=name:
                  aws_absent('iam', 'get-role', 'NoSuchEntity', RoleName=name))
        if owned.get('provider'):
            clean('delete-provider', lambda: api('iam', 'delete-open-id-connect-provider', OpenIDConnectProviderArn=owned['provider']))
            clean('verify-provider-absent', lambda:
                  aws_absent('iam', 'get-open-id-connect-provider', 'NoSuchEntity',
                             OpenIDConnectProviderArn=owned['provider']))
        evidence['cleanupCompletedAt'] = time.time()
        save()
    return {'fixture': str(output.relative_to(ROOT))}
