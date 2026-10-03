"""Actual official-agent, projected-token and AWS CLI pod credential workflow."""
import datetime
import json
import re
import time
import uuid
from urllib.parse import urlsplit

CLI_IMAGE = 'public.ecr.aws/aws-cli/aws-cli:2.31.6@sha256:1777475852370fb4fdb49a543314cb56cd0bd9c341741cca79b99166a7353a8f'


def require_authorization_denial(message):
    # An authority lookup canceled by transport is not a policy decision,
    # even if its upstream error was classified as AccessDenied.
    assert not re.search(r"\bcontext (?:canceled|deadline exceeded)\b", message), message
    match = re.search(r"\((AccessDenied(?:Exception)?|InvalidToken(?:Exception)?|ResourceNotFound(?:Exception)?|InvalidIdentityToken)\)(?=[: ])|Access Denied\.", message)
    assert match, message
    return match.group(1) or match.group(0)


def exercise_pod_identity(smoke, kube, cluster_name, node_name, node_role_name, restart, control_plane_update):
    """Run the caller's real control-plane update with live pods."""
    suffix = uuid.uuid4().hex[:8]
    namespace = 'pod-identity-' + suffix
    other_namespace = namespace + '-other'
    role_name = 'eks-pod-' + suffix
    target_name = role_name + '-target'
    deny_policy = 'pod-identity-deny-' + suffix
    role_policy = 'pod-workload'
    owned_roles, association_ids = [], []
    addon_owned, node_deny = False, False
    queue_url = None
    observed = smoke.data['observations'].setdefault('podIdentity', {})

    def call(label, service, operation, **values):
        return smoke.call('pod-identity-' + label, service, operation, **values)

    def apply(obj):
        return kube('apply', '-f', '-', stdin=json.dumps(obj))

    def pod(name='sdk', ns=namespace):
        return {'apiVersion': 'v1', 'kind': 'Pod', 'metadata': {'name': name, 'namespace': ns}, 'spec': {
            'serviceAccountName': 'sdk', 'nodeName': node_name, 'restartPolicy': 'Never',
            'containers': [{'name': 'sdk', 'image': CLI_IMAGE, 'imagePullPolicy': 'IfNotPresent',
                            'command': ['/bin/sh', '-c', 'while :; do sleep 3600; done'],
                            'env': [{'name': 'AWS_EC2_METADATA_DISABLED', 'value': 'true'}, {'name': 'AWS_DEFAULT_REGION', 'value': 'us-east-1'}, {'name': 'AWS_CA_BUNDLE', 'value': '/etc/stackd/ca.crt'}],
                            'volumeMounts': [{'name': 'root-ca', 'mountPath': '/etc/stackd', 'readOnly': True}]}],
            'volumes': [{'name': 'root-ca', 'configMap': {'name': 'root-ca'}}]}}

    def wait_pod(name='sdk', ns=namespace):
        kube('wait', '--for=condition=Ready', 'pod/' + name, '-n', ns, '--timeout=180s')

    def cli(*args, name='sdk', ns=namespace, success=True, token_file=None):
        prefix = ['exec', '-n', ns, name, '-c', 'sdk', '--']
        if token_file:
            prefix += ['env', 'AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE=' + token_file]
        text = kube(*prefix, 'aws', '--endpoint-url', smoke.guest_endpoint, '--region', 'us-east-1', *args, '--output', 'json', success=success)
        return json.loads(text) if success and text.strip() else text

    def identity(expected_role=role_name, name='sdk'):
        response = cli('sts', 'get-caller-identity', name=name)
        assert ':assumed-role/' + expected_role + '/' in response['Arn'], response
        return response['Arn']

    def trust(actions=('sts:AssumeRole', 'sts:TagSession'), allow=True, conditions=None):
        statement = {'Effect': 'Allow' if allow else 'Deny', 'Principal': {'Service': 'pods.eks.amazonaws.com'}, 'Action': list(actions)}
        if conditions is not None:
            statement['Condition'] = conditions
        return {'Version': '2012-10-17', 'Statement': [statement]}

    def update(**values):
        return call('update', 'eks', 'update_pod_identity_association', clusterName=cluster_name, associationId=association_ids[0], **values)['association']

    def denied(*args, **kwargs):
        message = cli(*args, success=False, **kwargs)
        code = require_authorization_denial(message)
        observed.setdefault('denials', []).append({'operation': list(args[:2]), 'namespace': kwargs.get('ns', namespace),
                                                 'pod': kwargs.get('name', 'sdk'), 'tokenFile': kwargs.get('token_file'),
                                                 'code': code, 'response': message})
        smoke.save()

    def wait_update(update_id, addon=False, expected='Successful'):
        for _ in range(240):
            values = {'name': cluster_name, 'updateId': update_id}
            if addon:
                values['addonName'] = 'eks-pod-identity-agent'
            result = call('update-state', 'eks', 'describe_update', **values)['update']
            if result['status'] != 'InProgress':
                assert result['status'] == expected, result
                return result
            time.sleep(1)
        raise RuntimeError('Pod identity smoke update did not finish')

    def daemonset():
        return json.loads(kube('get', 'daemonset', 'eks-pod-identity-agent', '-n', 'kube-system', '-o', 'json'))

    def agent_container(ds):
        return next(c for c in ds['spec']['template']['spec']['containers'] if c['name'] == 'eks-pod-identity-agent')

    def daemonset_patch(patch):
        kube('patch', 'daemonset', 'eks-pod-identity-agent', '-n', 'kube-system',
             '--field-manager=pod-identity-smoke-user', '--type=json', '-p', json.dumps(patch))

    try:
        for ns in [namespace, other_namespace]:
            apply({'apiVersion': 'v1', 'kind': 'Namespace', 'metadata': {'name': ns}})
            apply({'apiVersion': 'v1', 'kind': 'ServiceAccount', 'metadata': {'name': 'sdk', 'namespace': ns}})
            apply({'apiVersion': 'v1', 'kind': 'ConfigMap', 'metadata': {'name': 'root-ca', 'namespace': ns}, 'data': {'ca.crt': (smoke.state / 'server.crt').read_text()}})
        role = call('role', 'iam', 'create_role', RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust()))['Role']['Arn']
        owned_roles.append(role_name)
        queue_url = call('queue', 'sqs', 'create_queue', QueueName=role_name)['QueueUrl']
        queue_arn = call('queue-arn', 'sqs', 'get_queue_attributes', QueueUrl=queue_url, AttributeNames=['QueueArn'])['Attributes']['QueueArn']
        guest_queue = smoke.guest_endpoint + urlsplit(queue_url).path
        grant = {'Version': '2012-10-17', 'Statement': [{'Effect': 'Allow', 'Action': ['sqs:SendMessage'], 'Resource': queue_arn, 'Condition': {'StringEquals': {'aws:PrincipalTag/kubernetes-service-account': 'sdk', 'aws:PrincipalTag/kubernetes-namespace': namespace}}}]}
        call('role-policy', 'iam', 'put_role_policy', RoleName=role_name, PolicyName=role_policy, PolicyDocument=json.dumps(grant))
        association = call('create', 'eks', 'create_pod_identity_association', clusterName=cluster_name, namespace=namespace, serviceAccount='sdk', roleArn=role, clientRequestToken=str(uuid.uuid4()), tags={'probe': suffix})['association']
        association_ids.append(association['associationId'])
        agent_config = {'agent': {'additionalArgs': {'--max-cache-size': '0'}}, 'image': {'pullPolicy': 'IfNotPresent'}, 'resources': {'requests': {'cpu': '10m'}}}
        call('agent', 'eks', 'create_addon', clusterName=cluster_name, addonName='eks-pod-identity-agent', configurationValues=json.dumps(agent_config), resolveConflicts='OVERWRITE')
        addon_owned = True
        for _ in range(240):
            status = call('agent-ready', 'eks', 'describe_addon', clusterName=cluster_name, addonName='eks-pod-identity-agent')['addon']
            if status['status'] == 'ACTIVE':
                break
            if status['status'] not in ['CREATING', 'UPDATING']:
                raise RuntimeError('Agent failed: ' + json.dumps(status.get('health')))
            time.sleep(1)
        else:
            raise RuntimeError('Official pod identity agent readiness timed out')
        managed = daemonset()
        container_index = next(i for i, c in enumerate(managed['spec']['template']['spec']['containers']) if c['name'] == 'eks-pod-identity-agent')
        assert agent_container(managed)['resources']['requests']['cpu'] == '10m', managed
        daemonset_patch([{'op': 'replace', 'path': f'/spec/template/spec/containers/{container_index}/resources/requests/cpu', 'value': '15m'}])
        kube('rollout', 'status', 'daemonset/eks-pod-identity-agent', '-n', 'kube-system', '--timeout=180s')
        edited = daemonset()
        assert agent_container(edited)['resources']['requests']['cpu'] == '15m', edited
        agent_config['resources']['requests']['cpu'] = '20m'
        agent_config['podAnnotations'] = {'pod-identity-smoke/requested': suffix}
        conflict = call('agent-conflict', 'eks', 'update_addon', clusterName=cluster_name, addonName='eks-pod-identity-agent', configurationValues=json.dumps(agent_config), resolveConflicts='NONE')['update']
        failed = wait_update(conflict['id'], addon=True, expected='Failed')
        assert any(e['errorCode'] == 'ConfigurationConflict' for e in failed.get('errors', [])), failed
        assert daemonset()['spec'] == edited['spec'], 'NONE mutated the user-edited DaemonSet'
        preserved = call('agent-preserve', 'eks', 'update_addon', clusterName=cluster_name, addonName='eks-pod-identity-agent', configurationValues=json.dumps(agent_config), resolveConflicts='PRESERVE')['update']
        wait_update(preserved['id'], addon=True)
        live = daemonset()
        assert agent_container(live)['resources']['requests']['cpu'] == '15m', live
        assert live['spec']['template']['metadata']['annotations']['pod-identity-smoke/requested'] == suffix, live
        observed['agentSSAConflictAndFieldPreservation'] = {'userCPU': '15m', 'requestedAnnotation': suffix}
        apply(pod())
        wait_pod()
        uid_before = json.loads(kube('get', 'pod', 'sdk', '-n', namespace, '-o', 'json'))['metadata']['uid']
        request_tags = {'eks-cluster-arn': f'arn:aws:eks:us-east-1:{smoke.account}:cluster/{cluster_name}',
                        'eks-cluster-name': cluster_name, 'kubernetes-namespace': namespace,
                        'kubernetes-service-account': 'sdk', 'kubernetes-pod-name': 'sdk', 'kubernetes-pod-uid': uid_before}
        tag_conditions = {'StringEquals': {'aws:RequestTag/' + key: value for key, value in request_tags.items()},
                          'ForAllValues:StringEquals': {'aws:TagKeys': list(request_tags), 'sts:TransitiveTagKeys': list(request_tags)},
                          'Null': {'aws:TagKeys': 'false', 'sts:TransitiveTagKeys': 'false'}}
        call('request-tag-trust', 'iam', 'update_assume_role_policy', RoleName=role_name, PolicyDocument=json.dumps(trust(conditions=tag_conditions)))
        observed['firstSDKRoleARN'] = identity()
        observed['sixRequestTagsAndTagKeysTrust'] = True
        cli('sqs', 'send-message', '--queue-url', guest_queue, '--message-body', 'actual-pod-identity-' + suffix)
        messages = call('consume', 'sqs', 'receive_message', QueueUrl=queue_url, MaxNumberOfMessages=10).get('Messages', [])
        assert [m['Body'] for m in messages] == ['actual-pod-identity-' + suffix], messages
        observed['sessionTagAuthorizedRealSQSDelivery'] = True
        exported = json.loads(kube('exec', '-n', namespace, 'sdk', '-c', 'sdk', '--', 'aws', 'configure', 'export-credentials', '--format', 'process'))
        expiration = datetime.datetime.fromisoformat(exported['Expiration'].replace('Z', '+00:00'))
        observed['directSessionSecondsRemaining'] = round((expiration - datetime.datetime.now(datetime.timezone.utc)).total_seconds())
        del exported
        assert 21000 < observed['directSessionSecondsRemaining'] <= 21600
        restart()
        assert json.loads(kube('get', 'pod', 'sdk', '-n', namespace, '-o', 'json'))['metadata']['uid'] == uid_before
        observed['roleAfterControllerRestart'] = identity()
        retained = call('retained', 'eks', 'describe_pod_identity_association', clusterName=cluster_name, associationId=association_ids[0])['association']
        assert retained['associationArn'] == association['associationArn']
        # The caller owns the real control-plane upgrade and samples a live
        # UPDATING window. Do not manufacture one with retained-state writes.
        upgrade_conditions = json.loads(json.dumps(tag_conditions))
        del upgrade_conditions['StringEquals']['aws:RequestTag/kubernetes-pod-name']
        del upgrade_conditions['StringEquals']['aws:RequestTag/kubernetes-pod-uid']
        call('upgrade-trust', 'iam', 'update_assume_role_policy', RoleName=role_name, PolicyDocument=json.dumps(trust(conditions=upgrade_conditions)))
        role_before_update = identity()
        upgrade_pod_created = False

        def probe_updating():
            nonlocal upgrade_pod_created
            before = call('updating-before', 'eks', 'describe_cluster', name=cluster_name)['cluster']['status']
            if before != 'UPDATING':
                return {'observed': False, 'credentialsObserved': False, 'statusBefore': before, 'reason': 'UPDATING window ended before the pod probe'}
            refreshed_role = identity()
            assert refreshed_role != role_before_update, 'Agent returned a cached session despite max-cache-size=0'
            after_credentials = call('updating-after-credentials', 'eks', 'describe_cluster', name=cluster_name)['cluster']['status']
            kube('create', '-f', '-', stdin=json.dumps(pod(name='updating-sdk')))
            upgrade_pod_created = True
            admitted = json.loads(kube('get', 'pod', 'updating-sdk', '-n', namespace, '-o', 'json'))
            env = {entry['name']: entry.get('value') for entry in admitted['spec']['containers'][0]['env']}
            assert env['AWS_CONTAINER_CREDENTIALS_FULL_URI'] == 'http://169.254.170.23/v1/credentials', env
            assert env['AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE'] == '/var/run/secrets/pods.eks.amazonaws.com/serviceaccount/eks-pod-identity-token', env
            projected = next(v for v in admitted['spec']['volumes'] if v['name'] == 'eks-pod-identity-token')
            assert any(source.get('serviceAccountToken', {}).get('audience') == 'pods.eks.amazonaws.com' for source in projected['projected']['sources']), projected
            after = call('updating-after', 'eks', 'describe_cluster', name=cluster_name)['cluster']['status']
            result = {'observed': after == 'UPDATING', 'statusBefore': before, 'statusAfter': after,
                      'credentialsObserved': after_credentials == 'UPDATING', 'statusAfterCredentials': after_credentials,
                      'freshSDKRoleARN': refreshed_role, 'injectedPodUID': admitted['metadata']['uid']}
            if not result['observed']:
                result['reason'] = 'Native update completed before both pod operations were bracketed'
            return result

        observed['controlPlaneUpdate'] = control_plane_update(probe_updating)
        if upgrade_pod_created:
            wait_pod(name='updating-sdk')
            observed['admittedPodSDKRoleARN'] = identity(name='updating-sdk')
            kube('delete', 'pod', 'updating-sdk', '-n', namespace, '--wait=true')
        assert json.loads(kube('get', 'pod', 'sdk', '-n', namespace, '-o', 'json'))['metadata']['uid'] == uid_before
        call('restore-six-tag-trust', 'iam', 'update_assume_role_policy', RoleName=role_name, PolicyDocument=json.dumps(trust(conditions=tag_conditions)))
        observed['roleAfterControlPlaneUpgrade'] = identity()
        apply(pod(ns=other_namespace))
        wait_pod(ns=other_namespace)
        denied('sts', 'get-caller-identity', ns=other_namespace)
        observed['namespaceIsolation'] = True
        call('deny-node', 'iam', 'put_role_policy', RoleName=node_role_name, PolicyName=deny_policy, PolicyDocument=json.dumps({'Version': '2012-10-17', 'Statement': [{'Effect': 'Deny', 'Action': 'eks-auth:AssumeRoleForPodIdentity', 'Resource': '*'}]}))
        node_deny = True
        denied('sts', 'get-caller-identity')
        call('restore-node', 'iam', 'delete_role_policy', RoleName=node_role_name, PolicyName=deny_policy)
        node_deny = False
        identity()
        wrong_tags = json.loads(json.dumps(tag_conditions))
        wrong_tags['StringEquals']['aws:RequestTag/kubernetes-namespace'] = other_namespace
        call('wrong-request-tag-trust', 'iam', 'update_assume_role_policy', RoleName=role_name, PolicyDocument=json.dumps(trust(conditions=wrong_tags)))
        denied('sts', 'get-caller-identity')
        call('restore-request-tag-trust', 'iam', 'update_assume_role_policy', RoleName=role_name, PolicyDocument=json.dumps(trust(conditions=tag_conditions)))
        identity()
        call('revoke-trust', 'iam', 'update_assume_role_policy', RoleName=role_name, PolicyDocument=json.dumps(trust(allow=False)))
        denied('sts', 'get-caller-identity')
        call('untagged-trust', 'iam', 'update_assume_role_policy', RoleName=role_name, PolicyDocument=json.dumps(trust(actions=('sts:AssumeRole',))))
        denied('sts', 'get-caller-identity')
        update(disableSessionTags=True)
        absent_tags = {'Null': dict({'aws:RequestTag/' + key: 'true' for key in request_tags}, **{'aws:TagKeys': 'true', 'sts:TransitiveTagKeys': 'true'})}
        call('disabled-request-tags', 'iam', 'update_assume_role_policy', RoleName=role_name, PolicyDocument=json.dumps(trust(actions=('sts:AssumeRole',), conditions=absent_tags)))
        identity()
        denied('sqs', 'send-message', '--queue-url', guest_queue, '--message-body', 'must-not-send')
        observed['currentNodeTrustAndTagSessionAuthority'] = True
        external = 'us-east-1/' + smoke.account + '/' + cluster_name + '/' + namespace + '/sdk'
        target_trust = {'Version': '2012-10-17', 'Statement': [{'Effect': 'Allow', 'Principal': {'AWS': role}, 'Action': 'sts:AssumeRole', 'Condition': {'StringEquals': {'sts:ExternalId': external}}}]}
        target = call('target-role', 'iam', 'create_role', RoleName=target_name, AssumeRolePolicyDocument=json.dumps(target_trust))['Role']['Arn']
        owned_roles.append(target_name)
        call('target-policy', 'iam', 'put_role_policy', RoleName=target_name, PolicyName=role_policy, PolicyDocument=json.dumps({'Version': '2012-10-17', 'Statement': [{'Effect': 'Allow', 'Action': ['sqs:SendMessage', 'sqs:GetQueueAttributes'], 'Resource': queue_arn}]}))
        call('chain-policy', 'iam', 'put_role_policy', RoleName=role_name, PolicyName=role_policy, PolicyDocument=json.dumps({'Version': '2012-10-17', 'Statement': [{'Effect': 'Allow', 'Action': 'sts:AssumeRole', 'Resource': target}]}))
        restricted = {'Version': '2012-10-17', 'Statement': [{'Effect': 'Allow', 'Action': 'sqs:SendMessage', 'Resource': queue_arn}]}
        chained = update(targetRoleArn=target, policy=json.dumps(restricted))
        assert chained['externalId'] == external
        observed['targetSDKRoleARN'] = identity(target_name)
        cli('sqs', 'send-message', '--queue-url', guest_queue, '--message-body', 'target-role-' + suffix)
        denied('sqs', 'get-queue-attributes', '--queue-url', guest_queue, '--attribute-names', 'QueueArn')
        observed['targetExternalIDAndSessionPolicy'] = True
        exported = json.loads(kube('exec', '-n', namespace, 'sdk', '-c', 'sdk', '--', 'aws', 'configure', 'export-credentials', '--format', 'process'))
        expiration = datetime.datetime.fromisoformat(exported['Expiration'].replace('Z', '+00:00'))
        observed['targetSessionSecondsRemaining'] = round((expiration - datetime.datetime.now(datetime.timezone.utc)).total_seconds())
        del exported
        assert 3000 < observed['targetSessionSecondsRemaining'] <= 3600
        # A tagged target hop must inherit, not re-supply, all six attributes.
        # Ordinary STS enforces target TagSession as well as the first hop.
        tagged_target = json.loads(json.dumps(target_trust))
        tagged_target['Statement'][0]['Action'] = ['sts:AssumeRole', 'sts:TagSession']
        tagged_target['Statement'][0]['Condition'] = json.loads(json.dumps(tag_conditions))
        tagged_target['Statement'][0]['Condition']['StringEquals']['sts:ExternalId'] = external
        call('tagged-source-trust', 'iam', 'update_assume_role_policy', RoleName=role_name, PolicyDocument=json.dumps(trust(conditions=tag_conditions)))
        call('tagged-chain-policy', 'iam', 'put_role_policy', RoleName=role_name, PolicyName=role_policy, PolicyDocument=json.dumps({'Version': '2012-10-17', 'Statement': [{'Effect': 'Allow', 'Action': ['sts:AssumeRole', 'sts:TagSession'], 'Resource': target}]}))
        call('tagged-target-trust', 'iam', 'update_assume_role_policy', RoleName=target_name, PolicyDocument=json.dumps(tagged_target))
        call('tagged-target-policy', 'iam', 'put_role_policy', RoleName=target_name, PolicyName=role_policy, PolicyDocument=json.dumps(grant))
        update(disableSessionTags=False, policy='')
        observed['taggedTargetSDKRoleARN'] = identity(target_name)
        cli('sqs', 'send-message', '--queue-url', guest_queue, '--message-body', 'tagged-target-role-' + suffix)
        tagged_target['Statement'][0]['Action'] = ['sts:AssumeRole']
        call('deny-target-tags', 'iam', 'update_assume_role_policy', RoleName=target_name, PolicyDocument=json.dumps(tagged_target))
        denied('sts', 'get-caller-identity')
        observed['targetTransitiveRequestTagsAndTagSession'] = True
        update(disableSessionTags=True, policy=json.dumps(restricted))
        call('restore-untagged-source', 'iam', 'update_assume_role_policy', RoleName=role_name, PolicyDocument=json.dumps(trust(actions=('sts:AssumeRole',), conditions=absent_tags)))
        call('restore-untagged-target', 'iam', 'update_assume_role_policy', RoleName=target_name, PolicyDocument=json.dumps(target_trust))
        call('restore-target-policy', 'iam', 'put_role_policy', RoleName=target_name, PolicyName=role_policy, PolicyDocument=json.dumps({'Version': '2012-10-17', 'Statement': [{'Effect': 'Allow', 'Action': ['sqs:SendMessage', 'sqs:GetQueueAttributes'], 'Resource': queue_arn}]}))
        identity(target_name)
        for audience, bound in [('not-pods.eks.amazonaws.com', True), ('pods.eks.amazonaws.com', False)]:
            token_args = ['create', 'token', 'sdk', '-n', namespace, '--audience', audience]
            if bound:
                token_args += ['--bound-object-kind', 'Pod', '--bound-object-name', 'sdk', '--bound-object-uid', uid_before]
            invalid_token = kube(*token_args).strip()
            kube('exec', '-i', '-n', namespace, 'sdk', '-c', 'sdk', '--', 'sh', '-c', 'umask 077; cat > /tmp/invalid-token', stdin=invalid_token)
            del invalid_token
            denied('sts', 'get-caller-identity', token_file='/tmp/invalid-token')
        observed['wrongAudienceAndUnboundTokensRejected'] = True
        old_token = kube('exec', '-n', namespace, 'sdk', '-c', 'sdk', '--', 'cat', '/var/run/secrets/pods.eks.amazonaws.com/serviceaccount/eks-pod-identity-token').strip()
        kube('delete', 'pod', 'sdk', '-n', namespace, '--wait=true')
        apply(pod())
        wait_pod()
        assert json.loads(kube('get', 'pod', 'sdk', '-n', namespace, '-o', 'json'))['metadata']['uid'] != uid_before
        kube('exec', '-i', '-n', namespace, 'sdk', '-c', 'sdk', '--', 'sh', '-c', 'umask 077; cat > /tmp/old-token', stdin=old_token)
        del old_token
        denied('sts', 'get-caller-identity', token_file='/tmp/old-token')
        identity(target_name)
        kube('delete', 'serviceaccount', 'sdk', '-n', namespace)
        apply({'apiVersion': 'v1', 'kind': 'ServiceAccount', 'metadata': {'name': 'sdk', 'namespace': namespace}})
        denied('sts', 'get-caller-identity')
        kube('delete', 'pod', 'sdk', '-n', namespace, '--wait=true')
        apply(pod())
        wait_pod()
        identity(target_name)
        observed['podAndServiceAccountRecreationFenced'] = True
        call('delete-target-policy', 'iam', 'delete_role_policy', RoleName=target_name, PolicyName=role_policy)
        call('delete-target-role', 'iam', 'delete_role', RoleName=target_name)
        recreated_target = call('recreate-target-role', 'iam', 'create_role', RoleName=target_name, AssumeRolePolicyDocument=json.dumps(target_trust))['Role']['Arn']
        assert recreated_target == target
        call('recreate-target-policy', 'iam', 'put_role_policy', RoleName=target_name, PolicyName=role_policy, PolicyDocument=json.dumps({'Version': '2012-10-17', 'Statement': [{'Effect': 'Allow', 'Action': ['sqs:SendMessage', 'sqs:GetQueueAttributes'], 'Resource': queue_arn}]}))
        denied('sts', 'get-caller-identity')
        update(targetRoleArn=target)
        identity(target_name)
        call('delete-source-policy', 'iam', 'delete_role_policy', RoleName=role_name, PolicyName=role_policy)
        call('delete-source-role', 'iam', 'delete_role', RoleName=role_name)
        recreated_source = call('recreate-source-role', 'iam', 'create_role', RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust(actions=('sts:AssumeRole',))))['Role']['Arn']
        assert recreated_source == role
        call('recreate-source-policy', 'iam', 'put_role_policy', RoleName=role_name, PolicyName=role_policy, PolicyDocument=json.dumps({'Version': '2012-10-17', 'Statement': [{'Effect': 'Allow', 'Action': 'sts:AssumeRole', 'Resource': target}]}))
        denied('sts', 'get-caller-identity')
        update(roleArn=role)
        denied('sts', 'get-caller-identity')
        call('rebind-target-trust', 'iam', 'update_assume_role_policy', RoleName=target_name, PolicyDocument=json.dumps(target_trust))
        identity(target_name)
        observed['sourceAndTargetRoleRecreationFenced'] = True
        call('delete', 'eks', 'delete_pod_identity_association', clusterName=cluster_name, associationId=association_ids[0])
        association_ids.clear()
        denied('sts', 'get-caller-identity')
        observed['associationDeletionRevokesNewExchange'] = True
        smoke.save()
    finally:
        errors = []
        def clean(label, fn):
            try:
                fn()
            except Exception as error:
                errors.append(label + ': ' + str(error))
        if node_deny:
            clean('node-deny', lambda: call('cleanup-node-deny', 'iam', 'delete_role_policy', RoleName=node_role_name, PolicyName=deny_policy))
        for ns in [namespace, other_namespace]:
            clean(ns, lambda ns=ns: kube('delete', 'namespace', ns, '--ignore-not-found=true', '--wait=true'))
        for association_id in association_ids:
            clean('association', lambda association_id=association_id: call('cleanup-association', 'eks', 'delete_pod_identity_association', clusterName=cluster_name, associationId=association_id))
        if addon_owned:
            def delete_agent():
                call('cleanup-agent', 'eks', 'delete_addon', clusterName=cluster_name, addonName='eks-pod-identity-agent', preserve=False)
                smoke.client('eks').get_waiter('addon_deleted').wait(clusterName=cluster_name, addonName='eks-pod-identity-agent', WaiterConfig={'Delay': 2, 'MaxAttempts': 90})
            clean('agent', delete_agent)
        if queue_url:
            clean('queue', lambda: call('cleanup-queue', 'sqs', 'delete_queue', QueueUrl=queue_url))
        for role in reversed(owned_roles):
            clean(role + '-policy', lambda role=role: call('cleanup-role-policy', 'iam', 'delete_role_policy', RoleName=role, PolicyName=role_policy))
            clean(role, lambda role=role: call('cleanup-role', 'iam', 'delete_role', RoleName=role))
        observed['cleanupErrors'] = errors
        smoke.save()
        if errors:
            raise RuntimeError('Pod identity cleanup failed: ' + '; '.join(errors))
