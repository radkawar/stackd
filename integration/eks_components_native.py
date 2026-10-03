"""Exact-owned Fargate semantics; the caller owns cluster/subnets and capture output."""
import json
import time


def capture(aws, record, cluster_name, subnet_ids, until):
    role_name = cluster_name + '-fargate'
    profile_names = []
    role_created = False
    policy_attached = False
    policy = 'arn:aws:iam::aws:policy/AmazonEKSFargatePodExecutionRolePolicy'
    try:
        try:
            record('iam', 'get-role', RoleName='AWSServiceRoleForAmazonEKSForFargate')
        except RuntimeError as error:
            if 'NoSuchEntity' in str(error):
                return {'prerequisite': 'AWSServiceRoleForAmazonEKSForFargate absent; no service-linked role mutation performed'}
            raise
        trust = {'Version': '2012-10-17', 'Statement': [{'Effect': 'Allow', 'Principal': {'Service': 'eks-fargate-pods.amazonaws.com'}, 'Action': 'sts:AssumeRole'}]}
        role = record('iam', 'create-role', RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))['Role']['Arn']
        role_created = True
        record('iam', 'attach-role-policy', RoleName=role_name, PolicyArn=policy)
        policy_attached = True
        time.sleep(12)
        anomalies = []
        empty_selectors = {}
        try:
            empty = record('eks', 'create-fargate-profile', clusterName=cluster_name, fargateProfileName='native-empty-selectors', podExecutionRoleArn=role, subnets=subnet_ids, selectors=[])['fargateProfile']
            profile_names.append('native-empty-selectors')
            empty_selectors = {'accepted': True, 'profile': empty}
            until(lambda: aws('eks', 'describe-fargate-profile', clusterName=cluster_name, fargateProfileName='native-empty-selectors')['fargateProfile']['status'] != 'CREATING')
        except RuntimeError as error:
            empty_selectors = {'accepted': False, 'error': str(error)}
        for values in [
            {'fargateProfileName': 'eks-forbidden-capture', 'selectors': [{'namespace': 'native-*'}]},
            {'fargateProfileName': 'too-many-selectors', 'selectors': [{'namespace': f'native-{i}'} for i in range(6)]},
        ]:
            try:
                result = record('eks', 'create-fargate-profile', clusterName=cluster_name, podExecutionRoleArn=role, subnets=subnet_ids, **values)
            except RuntimeError:
                continue
            profile_names.append(values['fargateProfileName'])
            anomalies.append({'case': 'documented-invalid-admitted', 'profile': result})
        name = 'native-wildcards'
        request = {'clusterName': cluster_name, 'fargateProfileName': name, 'podExecutionRoleArn': role, 'subnets': subnet_ids, 'selectors': [{'namespace': 'native-*', 'labels': {'tier?': 'work*'}}], 'clientRequestToken': cluster_name + '-fargate-token', 'tags': {'stackd-capture': cluster_name}}
        first = record('eks', 'create-fargate-profile', **request)['fargateProfile']
        profile_names.append(name)
        replay = record('eks', 'create-fargate-profile', **request)['fargateProfile']
        if first['fargateProfileArn'] != replay['fargateProfileArn']:
            raise AssertionError('native idempotent create changed Fargate identity')
        def active():
            p = aws('eks', 'describe-fargate-profile', clusterName=cluster_name, fargateProfileName=name)['fargateProfile']
            if p['status'] == 'CREATE_FAILED':
                raise RuntimeError('native Fargate create failed: ' + json.dumps(p))
            return p if p['status'] == 'ACTIVE' else None
        until(active)
        record('eks', 'describe-fargate-profile', clusterName=cluster_name, fargateProfileName=name)
        record('eks', 'list-fargate-profiles', clusterName=cluster_name, maxResults=1)
        changed_replay = {}
        try:
            result = record('eks', 'create-fargate-profile', **dict(request, selectors=[{'namespace': 'different'}]))['fargateProfile']
            changed_replay = {'accepted': True, 'sameIdentity': result['fargateProfileArn'] == first['fargateProfileArn'], 'selectors': result.get('selectors')}
        except RuntimeError as error:
            changed_replay = {'accepted': False, 'error': str(error)}
        record('eks', 'delete-fargate-profile', clusterName=cluster_name, fargateProfileName=name)
        def absent():
            try:
                aws('eks', 'describe-fargate-profile', clusterName=cluster_name, fargateProfileName=name)
            except RuntimeError as error:
                if 'ResourceNotFoundException' in str(error):
                    return True
                raise
            return False
        until(absent)
        profile_names.remove(name)
        try:
            record('eks', 'describe-fargate-profile', clusterName=cluster_name, fargateProfileName=name)
        except RuntimeError as error:
            if 'ResourceNotFoundException' not in str(error):
                raise
        return {'profileLifecycle': 'observed', 'changedTokenReplay': changed_replay, 'emptySelectors': empty_selectors, 'anomalies': anomalies, 'pods': 'not exercised by native control capture'}
    finally:
        for name in profile_names:
            try:
                record('eks', 'delete-fargate-profile', clusterName=cluster_name, fargateProfileName=name)
            except RuntimeError as error:
                if 'ResourceNotFoundException' not in str(error):
                    raise
            def gone(name=name):
                try:
                    aws('eks', 'describe-fargate-profile', clusterName=cluster_name, fargateProfileName=name)
                except RuntimeError as error:
                    if 'ResourceNotFoundException' in str(error):
                        return True
                    raise
                return False
            until(gone)
        if policy_attached:
            record('iam', 'detach-role-policy', RoleName=role_name, PolicyArn=policy)
        if role_created:
            record('iam', 'delete-role', RoleName=role_name)
