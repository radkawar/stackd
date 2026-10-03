#!/usr/bin/env python3
"""Capture IAM policy discovery across ARN forms using an owned keyless user."""
import datetime
import json
import re
from pathlib import Path
import uuid

from aws_cli import run as run_cli, result as cli_result

OUTPUT = Path('.stackd/probes/iam/service_reference.json')


def call(service, operation, parameters):
    process = run_cli(service, operation, parameters, timeout=40,
                      options=["--region", "us-east-1", "--no-paginate"])
    if process.returncode:
        raise RuntimeError(operation + ': ' + process.stderr.strip())
    return cli_result(process)["output"]


def simulation_cases():
    cases = []
    scenarios = [('ec2:RunInstances', option, 'arn:aws:ec2:us-east-1:123456789012:instance/i-0123456789abcdef0') for option in [
        'EC2-Classic-EBS', 'EC2-Classic-InstanceStore', 'EC2-VPC-InstanceStore', 'EC2-VPC-InstanceStore-Subnet', 'EC2-VPC-EBS', 'EC2-VPC-EBS-Subnet', 'fictional', 'CloudWatch-Alarm']]
    scenarios += [(action, option, 'arn:aws:cloudwatch:us-east-1:123456789012:alarm:example')
                  for action in ['cloudwatch:ListTagsForResource', 'cloudwatch:TagResource', 'cloudwatch:UntagResource']
                  for option in ['CloudWatch-Alarm', 'CloudWatch-AlarmMuteRule', 'CloudWatch-InsightRule', 'CloudWatch-ServiceLevelObjective', 'CloudWatch-Dashboard', 'CloudWatch-Dataset', 'CloudWatch-MetricStream', 'CloudWatch-Service', 'fictional', 'EC2-VPC-EBS']]
    scenarios += [('devicefarm:ScheduleRun', option, 'arn:aws:devicefarm:us-west-2:123456789012:run:00000000-0000-0000-0000-000000000000/00000000-0000-0000-0000-000000000000') for option in ['Device Pool as filter', 'Device Selection Configuration as filter', 'fictional']]
    for action, option, resource in scenarios:
        parameters = {'ActionNames': [action], 'ResourceArns': [resource], 'ResourceHandlingOption': option,
                      'PolicyInputList': [json.dumps({'Version': '2012-10-17', 'Statement': [{'Effect': 'Allow', 'Action': '*', 'Resource': '*'}]})]}
        case = {'input': parameters}
        try:
            case['output'] = call('iam', 'simulate-custom-policy', parameters)
            case['code'] = 'Success'
        except RuntimeError as error:
            match = re.search(r'An error occurred \(([^)]+)\)', str(error))
            if not match:
                raise
            case['code'] = match[1]
        cases.append(case)
    return cases


def main():
    import argparse
    from aws_cli import require_account
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--account", required=True)
    probe_args = parser.parse_args()
    identity = require_account(probe_args.account)
    name = 'stackd-reference-' + uuid.uuid4().hex[:12]
    policies = {
        'http-authorizer': ('apigateway', 'apigateway:GET', 'arn:aws:apigateway:us-east-1::/apis/http123/authorizers/auth123'),
        'rest-authorizer': ('apigateway', 'apigateway:GET', 'arn:aws:apigateway:us-east-1::/restapis/rest123/authorizers/auth123'),
        'http-deployment': ('apigateway', 'apigateway:GET', 'arn:aws:apigateway:us-east-1::/apis/http123/deployments/deploy123'),
        'rest-deployment': ('apigateway', 'apigateway:GET', 'arn:aws:apigateway:us-east-1::/restapis/rest123/deployments/deploy123'),
        'green-deployment-v1': ('greengrass', 'greengrass:GetDeployment', 'arn:aws:greengrass:us-east-1:123456789012:/greengrass/groups/group123/deployments/deploy123'),
        'green-deployment-v2': ('greengrass', 'greengrass:GetDeployment', 'arn:aws:greengrass:us-east-1:123456789012:deployments:deploy123'),
        'different-service': ('sqs', 'apigateway:GET', 'arn:aws:sqs:us-east-1:123456789012:unrelated'),
    }
    documents = {}
    created = False
    attached = []
    capture = {'source': 'AWS IAM ListPoliciesGrantingServiceAccess',
               'region': 'us-east-1', 'retrieved_at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
               'scope': 'Keyless owned IAM user, inline policy resource forms; no API Gateway or Greengrass resources created.',
               'documentation': ['https://docs.aws.amazon.com/IAM/latest/APIReference/API_ListPoliciesGrantingServiceAccess.html',
                                 'https://docs.aws.amazon.com/service-authorization/latest/reference/service-reference.html'],
               'cleanup': False}
    try:
        user = call('iam', 'create-user', {'UserName': name})['User']
        created = True
        for key, (_, action, resource) in policies.items():
            document = {'Version': '2012-10-17', 'Statement': [{'Effect': 'Allow', 'Action': action, 'Resource': resource}]}
            call('iam', 'put-user-policy', {'UserName': name, 'PolicyName': key, 'PolicyDocument': json.dumps(document)})
            attached.append(key)
            documents[key] = document
        output = call('iam', 'list-policies-granting-service-access', {'Arn': user['Arn'], 'ServiceNamespaces': ['apigateway', 'greengrass', 'sqs']})
        capture['policies'] = documents
        for row in output['PoliciesGrantingServiceAccess']:
            for policy in row['Policies']:
                if policy.get('EntityName') == name:
                    policy['EntityName'] = 'reference'
        capture['result'] = output
        capture['simulation'] = simulation_cases()
    finally:
        for policy in attached:
            call('iam', 'delete-user-policy', {'UserName': name, 'PolicyName': policy})
        if created:
            call('iam', 'delete-user', {'UserName': name})
        capture['cleanup'] = True
        if 'result' in capture:
            OUTPUT.parent.mkdir(parents=True, exist_ok=True)
            OUTPUT.write_text(json.dumps(capture, indent=2) + '\n')
    for row in capture['result']['PoliciesGrantingServiceAccess']:
        print(row['ServiceNamespace'], sorted(p['PolicyName'] for p in row['Policies']))
    print('Owned IAM user and policies deleted')


if __name__ == '__main__':
    main()
