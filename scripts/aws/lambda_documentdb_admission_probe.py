#!/usr/bin/env python3
"""Capture native DocumentDB mapping admission without creating a billable cluster."""
import argparse
import base64
import datetime
import io
import json
import os
from pathlib import Path
import time
import uuid
import zipfile

from aws_cli import observe


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--account", required=True, help="AWS account ID that STS must match before native writes")
    parser.add_argument('--output', type=Path)
    parser.add_argument('--authority-only', action='store_true', help='Capture execution-role secret denial without repeating parameter cases')
    args = parser.parse_args()
    if args.output is None:
        args.output = Path('.stackd/probes/lambda/documentdb_authority.json' if args.authority_only else '.stackd/probes/lambda/documentdb_admission.json')
    env = dict(os.environ, AWS_REGION='us-east-1', AWS_DEFAULT_REGION='us-east-1', AWS_MAX_ATTEMPTS='1')
    prefix = 'stackd-next-docdblambda-' + uuid.uuid4().hex[:12]
    capture = {'source': 'Native AWS public endpoints through signed AWS CLI', 'started_at': datetime.datetime.now(datetime.timezone.utc).isoformat(), 'prefix': prefix, 'observations': [], 'cleanup': [], 'documentation': ['https://docs.aws.amazon.com/lambda/latest/dg/with-documentdb.html', 'https://docs.aws.amazon.com/lambda/latest/dg/invocation-eventfiltering.html', 'https://docs.aws.amazon.com/documentdb/latest/developerguide/using-lambda.html'], 'limitations': ['No native AWS DocumentDB cluster is created. Admission evidence is not delivery, network, filtering, or restart evidence.']}
    owned = {'role': False, 'policy': False, 'deny_policy': False, 'function': False, 'secret': None, 'mappings': []}

    def call(label, service, operation, request, cleanup=False):
        result = observe(service, operation, request, env)
        if operation == 'create-event-source-mapping' and result['code'] == 'Success':
            owned['mappings'].append(result['output']['UUID'])
        recorded = {key: ('[REDACTED]' if key == 'SecretString' else value) for key, value in request.items()}
        capture['cleanup' if cleanup else 'observations'].append({'label': label, 'service': service, 'operation': operation, 'input': recorded, 'result': result})
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(capture, indent=2) + '\n')
        print(label + ': ' + result['code'], flush=True)
        return result

    def require(result):
        if result['code'] != 'Success':
            raise RuntimeError(json.dumps(result))
        return result['output']

    try:
        identity = require(call('identity', 'sts', 'get-caller-identity', {}))
        if identity['Account'] != args.account:
            raise RuntimeError('Unexpected native account; no resources created')
        role = require(call('create_role', 'iam', 'create-role', {'RoleName': prefix, 'AssumeRolePolicyDocument': json.dumps({'Version': '2012-10-17', 'Statement': [{'Effect': 'Allow', 'Principal': {'Service': 'lambda.amazonaws.com'}, 'Action': 'sts:AssumeRole'}]})}))['Role']['Arn']
        owned['role'] = True
        policy = {'Version': '2012-10-17', 'Statement': [{'Effect': 'Allow', 'Resource': '*', 'Action': ['rds:DescribeDBClusters', 'rds:DescribeDBClusterParameters', 'rds:DescribeDBSubnetGroups', 'ec2:CreateNetworkInterface', 'ec2:DescribeNetworkInterfaces', 'ec2:DescribeVpcs', 'ec2:DeleteNetworkInterface', 'ec2:DescribeSubnets', 'ec2:DescribeSecurityGroups', 'secretsmanager:GetSecretValue']}]}
        require(call('put_policy', 'iam', 'put-role-policy', {'RoleName': prefix, 'PolicyName': prefix, 'PolicyDocument': json.dumps(policy)}))
        owned['policy'] = True
        package = io.BytesIO()
        with zipfile.ZipFile(package, 'w') as archive:
            archive.writestr('entry.py', 'def invoke(event, context):\n    return event\n')
        request = {'FunctionName': prefix, 'Role': role, 'Runtime': 'python3.12', 'Handler': 'entry.invoke', 'Timeout': 10, 'Code': {'ZipFile': base64.b64encode(package.getvalue()).decode()}}
        for attempt in range(20):
            result = call('create_function_' + str(attempt), 'lambda', 'create-function', request)
            if result['code'] == 'Success':
                owned['function'] = True
                break
            if result['code'] != 'InvalidParameterValueException':
                require(result)
            time.sleep(3)
        if not owned['function']:
            raise RuntimeError('Owned role did not propagate')
        for attempt in range(40):
            state = require(call('function_ready_' + str(attempt), 'lambda', 'get-function-configuration', {'FunctionName': prefix}))
            if state['State'] == 'Active':
                break
            time.sleep(1)
        else:
            raise RuntimeError('Owned function did not activate')
        source = f'arn:aws:rds:us-east-1:{args.account}:cluster:' + prefix
        secret = f'arn:aws:secretsmanager:us-east-1:{args.account}:secret:' + prefix + '-AbCdEf'
        base = {'FunctionName': prefix, 'EventSourceArn': source, 'StartingPosition': 'LATEST', 'Enabled': False, 'SourceAccessConfigurations': [{'Type': 'BASIC_AUTH', 'URI': secret}], 'DocumentDBEventSourceConfig': {'DatabaseName': 'owned', 'CollectionName': 'events', 'FullDocument': 'Default'}}
        cases = [('missing_documentdb_config', {'DocumentDBEventSourceConfig': None}), ('missing_database', {'DocumentDBEventSourceConfig': {'CollectionName': 'events'}}), ('missing_start', {'StartingPosition': None}), ('missing_secret', {'SourceAccessConfigurations': None}), ('timestamp_required', {'StartingPosition': 'AT_TIMESTAMP'}), ('timestamp_wrong_position', {'StartingPositionTimestamp': 1}), ('filter_unsupported', {'FilterCriteria': {'Filters': [{'Pattern': '{"event":{"operationType":["insert"]}}'}]}}), ('partial_batch_unsupported', {'FunctionResponseTypes': ['ReportBatchItemFailures']}), ('absent_cluster', {})]
        if args.authority_only:
            owned['secret'] = require(call('create_secret', 'secretsmanager', 'create-secret', {'Name': prefix, 'SecretString': json.dumps({'username': 'owned', 'password': uuid.uuid4().hex})}))['ARN']
            base['SourceAccessConfigurations'] = [{'Type': 'BASIC_AUTH', 'URI': owned['secret']}]
            call('available_secret_absent_cluster', 'lambda', 'create-event-source-mapping', base)
            deny = {'Version': '2012-10-17', 'Statement': [{'Effect': 'Deny', 'Action': 'secretsmanager:GetSecretValue', 'Resource': owned['secret']}]}
            require(call('deny_source_secret', 'iam', 'put-role-policy', {'RoleName': prefix, 'PolicyName': prefix + '-deny', 'PolicyDocument': json.dumps(deny)}))
            owned['deny_policy'] = True
            time.sleep(10)
            call('execution_role_secret_denied', 'lambda', 'create-event-source-mapping', base)
            require(call('restore_source_secret', 'iam', 'delete-role-policy', {'RoleName': prefix, 'PolicyName': prefix + '-deny'}))
            owned['deny_policy'] = False
            time.sleep(10)
            call('execution_role_secret_restored', 'lambda', 'create-event-source-mapping', base)
            cases = []
        for label, changes in cases:
            request = {key: value for key, value in dict(base, **changes).items() if value is not None}
            call(label, 'lambda', 'create-event-source-mapping', request)
    finally:
        for mapping in owned['mappings']:
            require(call('delete_mapping', 'lambda', 'delete-event-source-mapping', {'UUID': mapping}, True))
        if owned['function']:
            require(call('delete_function', 'lambda', 'delete-function', {'FunctionName': prefix}, True))
            if call('function_absent', 'lambda', 'get-function', {'FunctionName': prefix}, True)['code'] != 'ResourceNotFoundException':
                raise RuntimeError('Owned function remains')
        if owned['secret']:
            require(call('delete_secret', 'secretsmanager', 'delete-secret', {'SecretId': owned['secret'], 'ForceDeleteWithoutRecovery': True}, True))
            for attempt in range(20):
                result = call('secret_absent_' + str(attempt), 'secretsmanager', 'describe-secret', {'SecretId': owned['secret']}, True)
                if result['code'] == 'ResourceNotFoundException':
                    break
                require(result)
                time.sleep(1)
            else:
                raise RuntimeError('Owned secret remains')
        if owned['deny_policy']:
            require(call('delete_deny_policy', 'iam', 'delete-role-policy', {'RoleName': prefix, 'PolicyName': prefix + '-deny'}, True))
        if owned['policy']:
            require(call('delete_policy', 'iam', 'delete-role-policy', {'RoleName': prefix, 'PolicyName': prefix}, True))
        if owned['role']:
            require(call('delete_role', 'iam', 'delete-role', {'RoleName': prefix}, True))
            if call('role_absent', 'iam', 'get-role', {'RoleName': prefix}, True)['code'] != 'NoSuchEntity':
                raise RuntimeError('Owned role remains')


if __name__ == '__main__':
    main()
