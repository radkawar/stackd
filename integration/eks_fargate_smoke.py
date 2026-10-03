"""Real isolated per-Pod Fargate agents, selector routing, current trust and drain."""
import json


def exercise_fargate(aws, kube, cluster, subnet_ids, wait_for, restart, observed, image='busybox:1.37.0'):
    role_name = 'owned-fargate-workflow'
    name = 'owned-fargate'
    namespace = 'fg-owned'
    trust = {'Version': '2012-10-17', 'Statement': [{'Effect': 'Allow', 'Principal': {'Service': 'eks-fargate-pods.amazonaws.com'}, 'Action': 'sts:AssumeRole'}]}
    role = aws('iam', 'create-role', '--role-name', role_name, '--assume-role-policy-document', json.dumps(trust))['Role']['Arn']
    profile_created = False
    try:
        kube('create', 'namespace', namespace)
        request = {'clusterName': cluster, 'fargateProfileName': name, 'podExecutionRoleArn': role, 'subnets': subnet_ids, 'selectors': [{'namespace': 'fg-*', 'labels': {'tier?': 'job*'}}], 'clientRequestToken': 'owned-fargate-token'}
        profile = aws('eks', 'create-fargate-profile', '--cli-input-json', json.dumps(request))['fargateProfile']
        profile_created = True
        replay = aws('eks', 'create-fargate-profile', '--cli-input-json', json.dumps(request))['fargateProfile']
        assert profile['fargateProfileArn'] == replay['fargateProfileArn']
        def active():
            p = aws('eks', 'describe-fargate-profile', '--cluster-name', cluster, '--fargate-profile-name', name)['fargateProfile']
            if p['status'].endswith('FAILED'):
                raise RuntimeError(json.dumps(p))
            return p if p['status'] == 'ACTIVE' else None
        wait_for(active)
        def pod(pod_name, labels):
            return {'apiVersion': 'v1', 'kind': 'Pod', 'metadata': {'name': pod_name, 'namespace': namespace, 'labels': labels}, 'spec': {'containers': [{'name': 'work', 'image': image, 'command': ['sh', '-c', 'echo actual-isolated-fargate-output; sleep 3600']}]}}
        for pod_name, labels in [('selected-one', {'tier1': 'job-run'}), ('selected-two', {'tier2': 'job-other'}), ('not-selected', {'tier1': 'interactive'})]:
            kube('apply', '-f', '-', stdin=json.dumps(pod(pod_name, labels)))
        def running(pod_name):
            p = json.loads(kube('get', 'pod', pod_name, '-n', namespace, '-o', 'json'))
            return p if p['status'].get('phase') == 'Running' and all(c.get('ready') for c in p['status'].get('containerStatuses', [])) else None
        first = wait_for(lambda: running('selected-one'), 360)
        second = wait_for(lambda: running('selected-two'), 360)
        other = wait_for(lambda: running('not-selected'), 360)
        nodes = [first['spec']['nodeName'], second['spec']['nodeName']]
        assert len(set(nodes)) == 2 and other['spec']['nodeName'] not in nodes
        for selected in [first, second]:
            assert selected['metadata']['labels']['eks.amazonaws.com/fargate-profile'] == name
            node = json.loads(kube('get', 'node', selected['spec']['nodeName'], '-o', 'json'))
            assert node['metadata']['labels']['eks.amazonaws.com/compute-type'] == 'fargate'
            assert node['status']['capacity']['pods'] == '1'
            assert kube('logs', selected['metadata']['name'], '-n', namespace).strip() == 'actual-isolated-fargate-output'
        assert 'eks.amazonaws.com/fargate-profile' not in other['metadata'].get('labels', {})
        observed['fargateActualIsolatedNodes'] = nodes
        observed['fargateNonmatchingNode'] = other['spec']['nodeName']
        bad = pod('mismatch-request', {'tier1': 'interactive', 'eks.amazonaws.com/fargate-profile': name})
        assert 'does not match' in kube('create', '-f', '-', stdin=json.dumps(bad), success=False)
        denied_trust = {'Version': '2012-10-17', 'Statement': [{'Effect': 'Deny', 'Principal': {'Service': 'eks-fargate-pods.amazonaws.com'}, 'Action': 'sts:AssumeRole'}]}
        aws('iam', 'update-assume-role-policy', '--role-name', role_name, '--policy-document', json.dumps(denied_trust))
        denied = kube('create', '-f', '-', stdin=json.dumps(pod('trust-denied', {'tier1': 'job-new'})), success=False)
        assert 'denied' in denied.lower() or 'authorized' in denied.lower()
        aws('iam', 'update-assume-role-policy', '--role-name', role_name, '--policy-document', json.dumps(trust))
        wait_for(lambda: not aws('eks', 'describe-fargate-profile', '--cluster-name', cluster, '--fargate-profile-name', name)['fargateProfile'].get('health', {}).get('issues'))
        restart()
        wait_for(active)
        after = wait_for(lambda: running('selected-one'))
        assert after['metadata']['uid'] == first['metadata']['uid'] and after['spec']['nodeName'] == first['spec']['nodeName']
        assert kube('logs', 'selected-one', '-n', namespace).strip() == 'actual-isolated-fargate-output'
        observed['fargateCurrentRoleTrustAndRestart'] = True
        aws('eks', 'delete-fargate-profile', '--cluster-name', cluster, '--fargate-profile-name', name)
        wait_for(lambda: name not in aws('eks', 'list-fargate-profiles', '--cluster-name', cluster)['fargateProfileNames'], 360)
        profile_created = False
        for node in nodes:
            assert 'NotFound' in kube('get', 'node', node, success=False)
        for pod_name in ['selected-one', 'selected-two']:
            assert 'NotFound' in kube('get', 'pod', pod_name, '-n', namespace, success=False)
        assert running('not-selected')
        observed['fargateDrainAndNativeNodeRemoval'] = True
    except BaseException as error:
        diagnostic = {'failure': {'type': type(error).__name__, 'message': str(error)}}
        for label, collect in [
            ('profile', lambda: aws('eks', 'describe-fargate-profile', '--cluster-name', cluster, '--fargate-profile-name', name)),
            ('pods', lambda: json.loads(kube('get', 'pods', '-n', namespace, '-o', 'json'))),
            ('nodes', lambda: json.loads(kube('get', 'nodes', '-l', 'eks.amazonaws.com/fargate-profile=' + name, '-o', 'json'))),
            ('events', lambda: json.loads(kube('get', 'events', '-n', namespace, '-o', 'json'))),
        ]:
            try:
                diagnostic[label] = collect()
            except Exception as capture_error:
                diagnostic[label] = {'captureError': str(capture_error)}
        observed['fargateFailureBeforeCleanup'] = diagnostic
        raise
    finally:
        if profile_created:
            aws('eks', 'delete-fargate-profile', '--cluster-name', cluster, '--fargate-profile-name', name)
            wait_for(lambda: name not in aws('eks', 'list-fargate-profiles', '--cluster-name', cluster)['fargateProfileNames'], 360)
        kube('delete', 'namespace', namespace, '--ignore-not-found', '--wait=true')
        aws('iam', 'delete-role', '--role-name', role_name)
