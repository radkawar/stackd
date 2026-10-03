#!/usr/bin/env python3
"""Capture native EKS controls/events using exact-owned, automatically cleaned resources."""
import argparse
import importlib
import json
import pathlib
import subprocess
import time
import uuid


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--account', required=True)
    p.add_argument('--evidence', required=True)
    p.add_argument('--region', default='us-east-1')
    p.add_argument('--addon', action='append', default=[])
    p.add_argument('--settle-seconds', type=int, default=180)
    p.add_argument('--extension', action='append', default=[])
    a = p.parse_args()
    out = pathlib.Path(a.evidence)
    prefix = 'stackd-eks-depth-' + uuid.uuid4().hex[:10]
    evidence = {'prefix': prefix, 'region': a.region, 'calls': [], 'events': [], 'cleanup': []}
    owned = {'subnets': []}

    def save():
        out.write_text(json.dumps(evidence, indent=2) + '\n')

    def aws(service, action, **values):
        cmd = ['aws', service, action, '--region', a.region, '--output', 'json']
        if values:
            cmd += ['--cli-input-json', json.dumps(values)]
        run = subprocess.run(cmd, capture_output=True, text=True)
        if run.returncode:
            raise RuntimeError(f'{service} {action}: {run.stderr.strip()}')
        return json.loads(run.stdout) if run.stdout.strip() else {}

    def capture(service, action, **values):
        start = time.time()
        try:
            result = aws(service, action, **values)
            evidence['calls'].append({'service': service, 'operation': action, 'input': values, 'output': result, 'at': start})
            save()
            return result
        except Exception as err:
            evidence['calls'].append({'service': service, 'operation': action, 'input': values, 'error': str(err), 'at': start})
            save()
            raise

    def until(fn, timeout=1500):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            result = fn()
            if result:
                return result
            time.sleep(15)
        raise TimeoutError('native EKS lifecycle did not settle')

    def cleanup(action, fn):
        try:
            fn()
            evidence['cleanup'].append({'action': action, 'ok': True})
        except Exception as err:
            evidence['cleanup'].append({'action': action, 'error': str(err)})
        save()

    try:
        account = aws('sts', 'get-caller-identity')['Account']
        if account != a.account:
            raise RuntimeError('unexpected native account')
        aws('iam', 'get-role', RoleName='AWSServiceRoleForAmazonEKS')
        zones = aws('ec2', 'describe-availability-zones', Filters=[{'Name': 'state', 'Values': ['available']}])['AvailabilityZones']
        zones = [z['ZoneName'] for z in zones if z.get('ZoneType', 'availability-zone') == 'availability-zone']
        vpc = capture('ec2', 'create-vpc', CidrBlock='10.195.0.0/16', TagSpecifications=[{'ResourceType': 'vpc', 'Tags': [{'Key': 'Name', 'Value': prefix}]}])['Vpc']['VpcId']
        owned['vpc'] = vpc
        aws('ec2', 'modify-vpc-attribute', VpcId=vpc, EnableDnsHostnames={'Value': True})
        for i, zone in enumerate(zones[:2]):
            subnet = capture('ec2', 'create-subnet', VpcId=vpc, AvailabilityZone=zone, CidrBlock=f'10.195.{31+i}.0/24', TagSpecifications=[{'ResourceType': 'subnet', 'Tags': [{'Key': 'Name', 'Value': prefix}]}])['Subnet']['SubnetId']
            owned['subnets'].append(subnet)
        trust = {'Version': '2012-10-17', 'Statement': [{'Effect': 'Allow', 'Principal': {'Service': 'eks.amazonaws.com'}, 'Action': 'sts:AssumeRole'}]}
        role = capture('iam', 'create-role', RoleName=prefix, AssumeRolePolicyDocument=json.dumps(trust))['Role']['Arn']
        owned['role'] = prefix
        policy = 'arn:aws:iam::aws:policy/AmazonEKSClusterPolicy'
        aws('iam', 'attach-role-policy', RoleName=prefix, PolicyArn=policy)
        owned['policy'] = policy
        queue = capture('sqs', 'create-queue', QueueName=prefix)['QueueUrl']
        owned['queue'] = queue
        queue_arn = aws('sqs', 'get-queue-attributes', QueueUrl=queue, AttributeNames=['QueueArn'])['Attributes']['QueueArn']
        rule_arn = capture('events', 'put-rule', Name=prefix, EventPattern=json.dumps({'source': ['aws.eks']}))['RuleArn']
        owned['rule'] = prefix
        queue_policy = {'Version': '2012-10-17', 'Statement': [{'Effect': 'Allow', 'Principal': {'Service': 'events.amazonaws.com'}, 'Action': 'sqs:SendMessage', 'Resource': queue_arn, 'Condition': {'ArnEquals': {'aws:SourceArn': rule_arn}}}]}
        aws('sqs', 'set-queue-attributes', QueueUrl=queue, Attributes={'Policy': json.dumps(queue_policy)})
        aws('events', 'put-targets', Rule=prefix, Targets=[{'Id': 'capture', 'Arn': queue_arn}])
        versions = aws('eks', 'describe-cluster-versions')['clusterVersions']
        version = next(v['clusterVersion'] for v in versions if v.get('defaultVersion'))
        time.sleep(12)
        capture('eks', 'create-cluster', name=prefix, version=version, roleArn=role, resourcesVpcConfig={'subnetIds': owned['subnets']}, accessConfig={'authenticationMode': 'API', 'bootstrapClusterCreatorAdminPermissions': True}, logging={'clusterLogging': [{'types': ['api', 'audit', 'authenticator', 'controllerManager', 'scheduler'], 'enabled': True}]}, tags={'stackd-capture': prefix})
        owned['cluster'] = prefix
        cluster = until(lambda: (lambda c: c if c['status'] != 'CREATING' else None)(aws('eks', 'describe-cluster', name=prefix)['cluster']))
        evidence['cluster'] = cluster
        save()
        if cluster['status'] != 'ACTIVE':
            raise RuntimeError('native cluster failed: ' + cluster['status'])
        for module in a.extension:
            evidence.setdefault('extensions', {})[module] = importlib.import_module(module).capture(aws, capture, prefix, owned['subnets'], until)
            save()
        # DaemonSet-only add-ons can converge on an empty cluster; real AWS
        # observation decides success rather than assuming workloads exist.
        for addon in a.addon or ['eks-pod-identity-agent', 'kube-proxy']:
            capture('eks', 'create-addon', clusterName=prefix, addonName=addon, resolveConflicts='OVERWRITE')
            owned.setdefault('addons', []).append(addon)
            result = until(lambda: (lambda d: d if d['status'] not in ['CREATING', 'UPDATING'] else None)(aws('eks', 'describe-addon', clusterName=prefix, addonName=addon)['addon']), 900)
            evidence.setdefault('addons', []).append(result)
            save()
        for addon in owned.get('addons', [])[:]:
            capture('eks', 'delete-addon', clusterName=prefix, addonName=addon)
            owned['addons'].remove(addon)
        deadline = time.monotonic() + a.settle_seconds
        while time.monotonic() < deadline:
            result = aws('sqs', 'receive-message', QueueUrl=queue, MaxNumberOfMessages=10, WaitTimeSeconds=20)
            for msg in result.get('Messages', []):
                body = json.loads(msg['Body'])
                # Dedicated rule can see other EKS account activity; retain only
                # resources/details belonging to this exact capture prefix.
                if prefix in msg['Body']:
                    evidence['events'].append(body)
                aws('sqs', 'delete-message', QueueUrl=queue, ReceiptHandle=msg['ReceiptHandle'])
            save()
        evidence['logStreams'] = capture('logs', 'describe-log-streams', logGroupName=f'/aws/eks/{prefix}/cluster')['logStreams']
    except Exception as err:
        evidence['failure'] = str(err)
        save()
        raise
    finally:
        for addon in owned.get('addons', []):
            cleanup('delete addon ' + addon, lambda addon=addon: aws('eks', 'delete-addon', clusterName=prefix, addonName=addon))
        if owned.get('cluster'):
            cleanup('delete cluster', lambda: aws('eks', 'delete-cluster', name=prefix))
            def absent():
                try:
                    aws('eks', 'describe-cluster', name=prefix)
                    return False
                except RuntimeError as err:
                    if 'ResourceNotFoundException' in str(err): return True
                    raise
            cleanup('wait cluster deleted', lambda: until(absent))
            cleanup('delete native log group', lambda: aws('logs', 'delete-log-group', logGroupName=f'/aws/eks/{prefix}/cluster'))
        if owned.get('rule'):
            cleanup('remove event target', lambda: aws('events', 'remove-targets', Rule=prefix, Ids=['capture']))
            cleanup('delete event rule', lambda: aws('events', 'delete-rule', Name=prefix))
        if owned.get('queue'): cleanup('delete queue', lambda: aws('sqs', 'delete-queue', QueueUrl=owned['queue']))
        if owned.get('policy'): cleanup('detach role policy', lambda: aws('iam', 'detach-role-policy', RoleName=prefix, PolicyArn=owned['policy']))
        if owned.get('role'): cleanup('delete role', lambda: aws('iam', 'delete-role', RoleName=prefix))
        for subnet in owned['subnets']: cleanup('delete subnet ' + subnet, lambda subnet=subnet: aws('ec2', 'delete-subnet', SubnetId=subnet))
        if owned.get('vpc'):
            for group in aws('ec2', 'describe-security-groups', Filters=[{'Name': 'vpc-id', 'Values': [owned['vpc']]}])['SecurityGroups']:
                if group['GroupName'] != 'default': cleanup('delete cluster security group', lambda group=group: aws('ec2', 'delete-security-group', GroupId=group['GroupId']))
            cleanup('delete vpc', lambda: aws('ec2', 'delete-vpc', VpcId=owned['vpc']))
    print(json.dumps({'prefix': prefix, 'events': len(evidence['events']), 'cleanup': evidence['cleanup']}))


if __name__ == '__main__':
    main()
