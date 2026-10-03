"""Real CoreDNS installation, rollout, DNS, conflicts, preservation and removal."""
import json


def exercise_addons(aws, kube, cluster, wait_for, restart, observed):
    def addon():
        value = aws('eks', 'describe-addon', '--cluster-name', cluster, '--addon-name', 'coredns')['addon']
        if value['status'].endswith('FAILED'):
            raise RuntimeError(json.dumps(value))
        return value if value['status'] == 'ACTIVE' else None

    versions = aws('eks', 'describe-addon-versions', '--addon-name', 'coredns')['addons'][0]['addonVersions']
    assert {'v1.12.1-eksbuild.2', 'v1.12.3-eksbuild.1'} <= {v['addonVersion'] for v in versions}
    schema = aws('eks', 'describe-addon-configuration', '--addon-name', 'coredns', '--addon-version', 'v1.12.3-eksbuild.1')
    properties = json.loads(schema['configurationSchema'])['properties']
    assert properties['replicaCount']['type'] == 'integer' and 'minimum' not in properties['replicaCount']
    assert aws('eks', 'describe-addon-versions', '--addon-name', 'coredns', '--kubernetes-version', '1.32')['addons'] == []
    aws('eks', 'create-addon', '--cluster-name', cluster, '--addon-name', 'coredns', '--addon-version', 'v1.12.1-eksbuild.2', '--resolve-conflicts', 'OVERWRITE', '--configuration-values', '{"replicaCount":1}')
    wait_for(addon)
    deployment = json.loads(kube('get', 'deployment', 'coredns', '-n', 'kube-system', '-o', 'json'))
    assert deployment['spec']['template']['spec']['containers'][0]['image'].endswith(':1.12.1')
    dns = {'apiVersion': 'v1', 'kind': 'Pod', 'metadata': {'name': 'owned-addon-dns'}, 'spec': {'restartPolicy': 'Never', 'containers': [{'name': 'dns', 'image': 'busybox:1.37.0', 'command': ['sh', '-c', 'nslookup kubernetes.default.svc.cluster.local']}]}}
    kube('apply', '-f', '-', stdin=json.dumps(dns))
    wait_for(lambda: json.loads(kube('get', 'pod', 'owned-addon-dns', '-o', 'json'))['status'].get('phase') == 'Succeeded')
    output = kube('logs', 'owned-addon-dns')
    assert 'kubernetes.default.svc.cluster.local' in output and '10.43.0.1' in output
    observed['coreDNSActualLookup'] = output.strip()
    kube('delete', 'pod', 'owned-addon-dns', '--wait=true')
    aws('eks', 'update-addon', '--cluster-name', cluster, '--addon-name', 'coredns', '--configuration-values', '{"replicaCount":0}', '--resolve-conflicts', 'OVERWRITE')
    wait_for(addon)
    scaled_down = json.loads(kube('get', 'deployment', 'coredns', '-n', 'kube-system', '-o', 'json'))
    assert scaled_down['spec']['replicas'] == 0 and scaled_down['status'].get('availableReplicas', 0) == 0
    observed['coreDNSZeroReplicas'] = True
    controls = {'replicaCount': 2, 'computeType': 'ec2', 'resources': {'requests': {'cpu': '50m', 'memory': '64Mi'}}, 'nodeSelector': {'kubernetes.io/os': 'linux'}, 'podLabels': {'example.com/dns': 'managed'}, 'podAnnotations': {'example.com/config': 'native'}, 'podDisruptionBudget': {'enabled': True, 'maxUnavailable': 1}, 'annotationTopologyMode': 'Auto'}
    update = aws('eks', 'update-addon', '--cluster-name', cluster, '--addon-name', 'coredns', '--addon-version', 'v1.12.3-eksbuild.1', '--configuration-values', json.dumps(controls), '--resolve-conflicts', 'OVERWRITE')['update']
    params = {p['type']: p['value'] for p in update['params']}
    assert params == {'AddonVersion': 'v1.12.3-eksbuild.1', 'ConfigurationValues': json.dumps(controls), 'ResolveConflicts': 'OVERWRITE'}
    wait_for(addon)
    completion = aws('eks', 'describe-update', '--name', cluster, '--addon-name', 'coredns', '--update-id', update['id'])['update']
    assert completion['status'] == 'Successful'
    deployment = json.loads(kube('get', 'deployment', 'coredns', '-n', 'kube-system', '-o', 'json'))
    assert deployment['status']['availableReplicas'] == 2
    assert deployment['spec']['template']['spec']['containers'][0]['image'].endswith(':1.12.3')
    template = deployment['spec']['template']
    assert template['metadata']['labels']['example.com/dns'] == 'managed'
    assert template['metadata']['annotations']['example.com/config'] == 'native'
    assert template['metadata']['annotations']['eks.amazonaws.com/compute-type'] == 'ec2'
    assert template['spec']['containers'][0]['resources']['requests'] == controls['resources']['requests']
    assert json.loads(kube('get', 'pdb', 'coredns', '-n', 'kube-system', '-o', 'json'))['spec']['maxUnavailable'] == 1
    assert json.loads(kube('get', 'service', 'kube-dns', '-n', 'kube-system', '-o', 'json'))['metadata']['annotations']['service.kubernetes.io/topology-mode'] == 'Auto'
    bad = dict(controls, nodeSelector={'stackd.eks/no-such-node': 'true'})
    broken = aws('eks', 'update-addon', '--cluster-name', cluster, '--addon-name', 'coredns', '--addon-version', 'v1.12.1-eksbuild.2', '--configuration-values', json.dumps(bad), '--resolve-conflicts', 'OVERWRITE')['update']
    def rolled_back():
        value = aws('eks', 'describe-update', '--name', cluster, '--addon-name', 'coredns', '--update-id', broken['id'])['update']
        return value if value['status'] != 'InProgress' else None
    failure = wait_for(rolled_back)
    assert failure['status'] == 'Failed' and failure['errors'][0]['errorCode'] == 'InsufficientNumberOfReplicas'
    restored = json.loads(kube('get', 'deployment', 'coredns', '-n', 'kube-system', '-o', 'json'))
    assert restored['spec']['template']['spec']['containers'][0]['image'].endswith(':1.12.3')
    assert 'stackd.eks/no-such-node' not in restored['spec']['template']['spec']['nodeSelector']
    assert restored['status']['availableReplicas'] >= 2
    assert aws('eks', 'describe-addon', '--cluster-name', cluster, '--addon-name', 'coredns')['addon']['status'] == 'UPDATE_FAILED'
    observed['coreDNSFailedRolloutRestoredActualDeployment'] = True
    aws('eks', 'update-addon', '--cluster-name', cluster, '--addon-name', 'coredns', '--configuration-values', json.dumps(controls), '--resolve-conflicts', 'OVERWRITE')
    wait_for(addon)
    config = json.loads(kube('get', 'configmap', 'coredns', '-n', 'kube-system', '-o', 'json'))['data']['Corefile'] + '\n# externally-managed-field\n'
    kube('patch', 'configmap', 'coredns', '-n', 'kube-system', '--type=merge', '-p', json.dumps({'data': {'Corefile': config}}))
    # Supporting objects also carry real field ownership, not only the deployment.
    rules = json.loads(kube('get', 'clusterrole', 'system:coredns', '-o', 'json'))['rules']
    rules.append({'apiGroups': [''], 'resources': ['configmaps'], 'verbs': ['get']})
    kube('patch', 'clusterrole', 'system:coredns', '--type=merge', '-p', json.dumps({'rules': rules}))
    conflict = aws('eks', 'update-addon', '--cluster-name', cluster, '--addon-name', 'coredns', '--configuration-values', '{"replicaCount":1}', '--resolve-conflicts', 'NONE')['update']
    def conflicted():
        value = aws('eks', 'describe-update', '--name', cluster, '--addon-name', 'coredns', '--update-id', conflict['id'])['update']
        return value if value['status'] != 'InProgress' else None
    failure = wait_for(conflicted)
    assert failure['status'] == 'Failed' and failure['errors'][0]['errorCode'] == 'ConfigurationConflict'
    assert json.loads(kube('get', 'configmap', 'coredns', '-n', 'kube-system', '-o', 'json'))['data']['Corefile'] == config
    assert json.loads(kube('get', 'clusterrole', 'system:coredns', '-o', 'json'))['rules'] == rules
    aws('eks', 'update-addon', '--cluster-name', cluster, '--addon-name', 'coredns', '--configuration-values', '{"replicaCount":1}', '--resolve-conflicts', 'PRESERVE')
    wait_for(addon)
    assert json.loads(kube('get', 'configmap', 'coredns', '-n', 'kube-system', '-o', 'json'))['data']['Corefile'] == config
    assert json.loads(kube('get', 'clusterrole', 'system:coredns', '-o', 'json'))['rules'] == rules
    restart()
    wait_for(addon)
    observed['coreDNSVersionRolloutAndRestart'] = 'v1.12.1-eksbuild.2 -> v1.12.3-eksbuild.1'
    observed['coreDNSConflictPreserved'] = True
    aws('eks', 'delete-addon', '--cluster-name', cluster, '--addon-name', 'coredns', '--preserve')
    wait_for(lambda: 'coredns' not in aws('eks', 'list-addons', '--cluster-name', cluster)['addons'])
    assert json.loads(kube('get', 'deployment', 'coredns', '-n', 'kube-system', '-o', 'json'))['status']['availableReplicas'] == 1
    aws('eks', 'create-addon', '--cluster-name', cluster, '--addon-name', 'coredns', '--resolve-conflicts', 'OVERWRITE')
    wait_for(addon)
    aws('eks', 'delete-addon', '--cluster-name', cluster, '--addon-name', 'coredns')
    wait_for(lambda: 'coredns' not in aws('eks', 'list-addons', '--cluster-name', cluster)['addons'])
    assert 'NotFound' in kube('get', 'deployment', 'coredns', '-n', 'kube-system', success=False)
    observed['coreDNSNativeRemoval'] = True
    # Restore working self-managed DNS for the caller's later workload scenarios.
    aws('eks', 'create-addon', '--cluster-name', cluster, '--addon-name', 'coredns', '--resolve-conflicts', 'OVERWRITE')
    wait_for(addon)
    aws('eks', 'delete-addon', '--cluster-name', cluster, '--addon-name', 'coredns', '--preserve')
    wait_for(lambda: 'coredns' not in aws('eks', 'list-addons', '--cluster-name', cluster)['addons'])
