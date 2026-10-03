#!/usr/bin/env python3
"""Calibrate owned AWS Lambda /tmp capacity; writes at most 600 MiB once."""
import argparse
import base64
import datetime
import io
import json
import os
from pathlib import Path
import tempfile
import time
import uuid
import zipfile

from aws_cli import observe, result, run

HANDLER = '''import errno, os

def stat():
    s = os.statvfs('/tmp')
    return {'block_size': s.f_frsize, 'total_bytes': s.f_blocks * s.f_frsize,
            'available_bytes': s.f_bavail * s.f_frsize, 'free_bytes': s.f_bfree * s.f_frsize}

def invoke(event, context):
    result = {'before': stat(), 'memory_mb': context.memory_limit_in_mb,
              'mounts': [line.strip() for line in open('/proc/mounts') if line.split()[1] == '/tmp']}
    if event.get('fill'):
        count = 0
        chunk = b'x' * (1024 * 1024)
        try:
            with open('/tmp/owned-fill', 'wb', buffering=0) as f:
                while count < 600 * 1024 * 1024:
                    count += f.write(chunk)
            raise RuntimeError('bounded probe did not reach disk full')
        except OSError as e:
            if e.errno != errno.ENOSPC:
                raise
            result['errno'] = e.errno
        result['written_bytes'] = count
        result['full'] = stat()
        allocation = bytearray(64 * 1024 * 1024)
        for i in range(0, len(allocation), 4096): allocation[i] = 1
        result['allocation_bytes'] = len(allocation)
        os.remove('/tmp/owned-fill')
        result['after'] = stat()
    return result
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--account", required=True, help="AWS account ID that STS must match before native writes")
    parser.add_argument('--output', type=Path, default=Path('.stackd/probes/lambda/ephemeral_storage.json'))
    args = parser.parse_args()
    env = dict(os.environ, AWS_REGION='us-east-1', AWS_DEFAULT_REGION='us-east-1', AWS_MAX_ATTEMPTS='1')
    prefix = 'stackd-lambda-tmp-' + uuid.uuid4().hex[:12]
    capture = {'source': 'Native AWS public endpoints through scripts/aws/aws_cli.py',
               'started_at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
               'prefix': prefix, 'observations': [], 'cleanup': [],
               'limits': 'One 512 MiB configured filesystem filled with at most 600 MiB writes; 10 GiB configuration stat only. No logging policy.'}
    owned = {'role': False, 'function': False}

    def save():
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(capture, indent=2) + '\n')

    def call(label, service, operation, request, cleanup=False):
        response = observe(service, operation, request, env)
        capture['cleanup' if cleanup else 'observations'].append({'label': label, 'service': service, 'operation': operation, 'input': request, 'result': response})
        save()
        print(label + ': ' + response['code'], flush=True)
        return response

    def require(response):
        if response['code'] != 'Success':
            raise RuntimeError(json.dumps(response))
        return response['output']

    def ready(label):
        for attempt in range(60):
            state = require(call(label + str(attempt), 'lambda', 'get-function-configuration', {'FunctionName': prefix}))
            if state['State'] == 'Active' and state.get('LastUpdateStatus', 'Successful') == 'Successful':
                return
            if state['State'] == 'Failed' or state.get('LastUpdateStatus') == 'Failed':
                raise RuntimeError(json.dumps(state))
            time.sleep(1)
        raise RuntimeError('Owned function did not become ready')

    def invoke(label, fill, directory):
        output_file = directory / (label + '.json')
        payload = {'fill': fill}
        response = result(run('lambda', 'invoke', env=env,
            options=['--function-name', prefix, '--payload', json.dumps(payload), '--cli-binary-format', 'raw-in-base64-out', str(output_file)], timeout=45), cli_message=None)
        if response['code'] == 'Success':
            data = output_file.read_bytes()
            response['payload_base64'] = base64.b64encode(data).decode()
            response['output']['Payload'] = json.loads(data)
        capture['observations'].append({'label': label, 'service': 'lambda', 'operation': 'invoke', 'input': {'FunctionName': prefix, 'Payload': payload}, 'result': response})
        save()
        output = require(response)
        print(label + ': ' + json.dumps(output), flush=True)
        if 'FunctionError' in output:
            raise RuntimeError('Native capacity handler failed')

    try:
        identity = require(call('identity', 'sts', 'get-caller-identity', {}))
        if identity['Account'] != args.account:
            raise RuntimeError('Unexpected AWS account; no resources created')
        role = require(call('create_role', 'iam', 'create-role', {'RoleName': prefix,
            'AssumeRolePolicyDocument': json.dumps({'Version': '2012-10-17', 'Statement': [{'Effect': 'Allow', 'Principal': {'Service': 'lambda.amazonaws.com'}, 'Action': 'sts:AssumeRole'}]})}))['Role']['Arn']
        owned['role'] = True
        package = io.BytesIO()
        with zipfile.ZipFile(package, 'w') as archive:
            archive.writestr('entry.py', HANDLER)
        request = {'FunctionName': prefix, 'Role': role, 'Runtime': 'python3.12', 'Handler': 'entry.invoke',
                   'Timeout': 30, 'MemorySize': 128, 'EphemeralStorage': {'Size': 512},
                   'Code': {'ZipFile': base64.b64encode(package.getvalue()).decode()}}
        for attempt in range(20):
            response = call('create_function_' + str(attempt), 'lambda', 'create-function', request)
            if response['code'] == 'Success':
                owned['function'] = True
                break
            if response['code'] != 'InvalidParameterValueException':
                require(response)
            time.sleep(3)
        if not owned['function']:
            raise RuntimeError('Owned role did not propagate')
        ready('ready_512_')
        with tempfile.TemporaryDirectory(prefix='stackd-lambda-tmp-probe-') as temporary:
            invoke('fill_512', True, Path(temporary))
            require(call('configure_10240', 'lambda', 'update-function-configuration', {'FunctionName': prefix, 'EphemeralStorage': {'Size': 10240}}))
            ready('ready_10240_')
            invoke('stat_10240', False, Path(temporary))
    finally:
        errors = []
        if owned['function']:
            response = call('delete_function', 'lambda', 'delete-function', {'FunctionName': prefix}, True)
            if response['code'] != 'Success': errors.append(response)
            response = call('function_absent', 'lambda', 'get-function', {'FunctionName': prefix}, True)
            if response['code'] != 'ResourceNotFoundException': errors.append(response)
        if owned['role']:
            response = call('delete_role', 'iam', 'delete-role', {'RoleName': prefix}, True)
            if response['code'] != 'Success': errors.append(response)
            response = call('role_absent', 'iam', 'get-role', {'RoleName': prefix}, True)
            if response['code'] != 'NoSuchEntity': errors.append(response)
        if errors:
            raise RuntimeError('Native owned cleanup failed: ' + json.dumps(errors))


if __name__ == '__main__':
    main()
