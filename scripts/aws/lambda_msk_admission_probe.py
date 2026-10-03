#!/usr/bin/env python3
"""Capture cheap Lambda/Kafka admission boundaries; never creates a Kafka broker."""
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
    parser.add_argument('--source-kind', choices=['msk', 'self-managed'], default='msk')
    args = parser.parse_args()
    if args.output is None:
        args.output = Path('.stackd/probes/lambda/' + ('msk' if args.source_kind == 'msk' else 'self_managed_kafka') + '_admission.json')
    env = dict(os.environ, AWS_REGION='us-east-1', AWS_DEFAULT_REGION='us-east-1', AWS_MAX_ATTEMPTS='1')
    prefix = 'stackd-next-lambda-' + uuid.uuid4().hex[:12]
    capture = {'source': 'Native AWS public endpoints through scripts/aws/aws_cli.py', 'started_at': datetime.datetime.now(datetime.timezone.utc).isoformat(), 'prefix': prefix, 'observations': [], 'cleanup': [], 'documentation': ['https://docs.aws.amazon.com/lambda/latest/dg/msk-esm-parameters.html', 'https://docs.aws.amazon.com/lambda/latest/dg/kafka-consumer-group-id.html'], 'limitations': ['No native MSK cluster is created; these observations establish admission ordering and boundaries only, not delivery.']}
    owned = {'role': False, 'function': False, 'mappings': []}
    if args.source_kind == 'self-managed':
        capture['documentation'] = ['https://docs.aws.amazon.com/lambda/latest/dg/kafka-esm-parameters.html', 'https://docs.aws.amazon.com/lambda/latest/dg/kafka-cluster-auth.html']
        capture['limitations'] = ['No native Kafka cluster is created; disabled public-endpoint mappings establish admission only, not broker delivery.']

    def call(label, service, operation, request, cleanup=False):
        result = observe(service, operation, request, env)
        capture['cleanup' if cleanup else 'observations'].append({'label': label, 'service': service, 'operation': operation, 'input': request, 'result': result})
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
        source = f'arn:aws:kafka:us-east-1:{args.account}:cluster/' + prefix + '/' + str(uuid.uuid4()) + '-2'
        base = {'FunctionName': prefix, 'EventSourceArn': source, 'Topics': ['owned-topic'], 'StartingPosition': 'TRIM_HORIZON', 'Enabled': False}
        cases = [('missing_topics', {'Topics': None}), ('multiple_topics', {'Topics': ['one', 'two']}), ('invalid_topic', {'Topics': ['bad/topic']}), ('missing_start', {'StartingPosition': None}), ('timestamp_required', {'StartingPosition': 'AT_TIMESTAMP'}), ('timestamp_wrong_position', {'StartingPositionTimestamp': 1}), ('queue_options', {'Queues': ['queue']}), ('empty_group', {'AmazonManagedKafkaEventSourceConfig': {'ConsumerGroupId': ''}}), ('absent_cluster', {})]
        if args.source_kind == 'self-managed':
            base.pop('EventSourceArn')
            base['SelfManagedEventSource'] = {'Endpoints': {'KAFKA_BOOTSTRAP_SERVERS': ['kafka.example.com:9092']}}
            cases = [
                ('missing_topics', {'Topics': None}), ('multiple_topics', {'Topics': ['one', 'two']}),
                ('invalid_topic', {'Topics': ['bad/topic']}), ('missing_start', {'StartingPosition': None}),
                ('timestamp_required', {'StartingPosition': 'AT_TIMESTAMP'}),
                ('timestamp_wrong_position', {'StartingPositionTimestamp': 1}), ('queue_options', {'Queues': ['queue']}),
                ('empty_group', {'SelfManagedKafkaEventSourceConfig': {'ConsumerGroupId': ''}}),
                ('mixed_source_arn', {'EventSourceArn': source}),
                ('missing_bootstrap', {'SelfManagedEventSource': {'Endpoints': {}}}),
                ('invalid_bootstrap', {'SelfManagedEventSource': {'Endpoints': {'KAFKA_BOOTSTRAP_SERVERS': ['https://kafka.example.com:9092']}}}),
                ('disabled_public_source', {}),
            ]
        for label, changes in cases:
            request = dict(base, **changes)
            request = {key: value for key, value in request.items() if value is not None}
            result = call(label, 'lambda', 'create-event-source-mapping', request)
            if result['code'] == 'Success':
                owned['mappings'].append(result['output']['UUID'])
    finally:
        for mapping in owned['mappings']:
            result = call('delete_mapping', 'lambda', 'delete-event-source-mapping', {'UUID': mapping}, True)
            if result['code'] == 'Success':
                for attempt in range(90):
                    result = call('mapping_absent_' + str(attempt), 'lambda', 'get-event-source-mapping', {'UUID': mapping}, True)
                    if result['code'] == 'ResourceNotFoundException':
                        break
                    time.sleep(2)
                else:
                    raise RuntimeError('Owned mapping remains')
        if owned['function']:
            require(call('delete_function', 'lambda', 'delete-function', {'FunctionName': prefix}, True))
            result = call('function_absent', 'lambda', 'get-function', {'FunctionName': prefix}, True)
            if result['code'] != 'ResourceNotFoundException':
                raise RuntimeError('Owned function remains')
        if owned['role']:
            require(call('delete_role', 'iam', 'delete-role', {'RoleName': prefix}, True))
            result = call('role_absent', 'iam', 'get-role', {'RoleName': prefix}, True)
            if result['code'] != 'NoSuchEntity':
                raise RuntimeError('Owned role remains')


if __name__ == '__main__':
    main()
