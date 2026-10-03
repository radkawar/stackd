#!/usr/bin/env python3
"""Exercise real durable SDK checkpoints, waits, callbacks and external SQS effects."""
import argparse
import base64
import datetime
import io
import json
import os
from pathlib import Path
import sys
import time
import uuid
import zipfile

HANDLER = '''import json, boto3
from aws_durable_execution_sdk_python import durable_execution
from aws_durable_execution_sdk_python.config import CallbackConfig, Duration
sqs = boto3.client("sqs")

@durable_execution
def handler(event, context):
    def emit(kind, extra=None):
        body = {"run": event["run"], "kind": kind}
        body.update(extra or {})
        sqs.send_message(QueueUrl=event["queue"], MessageBody=json.dumps(body))
        return kind
    context.step(lambda _: emit("before"), name="before-effect")
    context.wait(Duration.from_seconds(event.get("wait", 1)), name="timer")
    callback = context.create_callback(name="approval", config=CallbackConfig(
        timeout=Duration.from_seconds(180), heartbeat_timeout=Duration.from_seconds(60)))
    context.step(lambda _: emit("callback", {"callback": callback.callback_id}), name="callback-effect")
    approval = callback.result()
    context.step(lambda _: emit("after", {"approval": approval}), name="after-effect")
    return {"run": event["run"], "approval": approval}
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--account", help="Required for native AWS; STS must match before native writes")
    parser.add_argument('--sdk-directory', type=Path, required=True)
    parser.add_argument('--output', type=Path, default=Path('.stackd/probes/lambda/durable_execution.json'))
    parser.add_argument('--endpoint-url')
    parser.add_argument('--prefix')
    parser.add_argument('--kms-key-arn')
    parser.add_argument('--cleanup-gate', type=Path)
    args = parser.parse_args()
    if not args.endpoint_url and not args.account:
        parser.error("--account is required for native AWS")
    sys.path.insert(0, str(args.sdk_directory.resolve()))
    import boto3
    from botocore.config import Config
    from botocore.exceptions import ClientError
    settings = {'region_name': 'us-east-1', 'config': Config(retries={'max_attempts': 0}, read_timeout=200)}
    if args.endpoint_url:
        settings['endpoint_url'] = args.endpoint_url
    clients = {name: boto3.client(name, **settings) for name in ('sts', 'iam', 'lambda', 'sqs')}
    prefix = args.prefix or ('stackd-next-durable-' + uuid.uuid4().hex[:10])
    capture = {'source': 'AWS public signed boto3 and aws-durable-execution-sdk-python 2.0.1' if not args.endpoint_url else 'stackd signed boto3 and real durable SDK runtime',
               'started_at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
               'prefix': prefix, 'observations': [], 'cleanup': []}
    owned = {}

    def redacted(value):
        if isinstance(value, dict):
            return {key: ('<redacted>' if key in ('CallbackId', 'CheckpointToken', 'Location') else redacted(item)) for key, item in value.items()}
        if isinstance(value, list):
            return [redacted(item) for item in value]
        return value

    def save():
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(redacted(capture), indent=2, default=str) + '\n')

    def call(label, service, operation, request, cleanup=False, expected=None):
        entry = {'label': label, 'operation': operation}
        try:
            output = getattr(clients[service], operation)(**request)
            entry['request_id'] = output.pop('ResponseMetadata', {}).get('RequestId')
            if 'Payload' in output and hasattr(output['Payload'], 'read'):
                output['Payload'] = output['Payload'].read().decode()
            entry.update(code='Success', output=output)
        except ClientError as err:
            entry.update(code=err.response['Error']['Code'], message=err.response['Error']['Message'])
            entry['request_id'] = err.response.get('ResponseMetadata', {}).get('RequestId')
            output = None
        capture['cleanup' if cleanup else 'observations'].append(entry)
        save()
        print(label + ': ' + entry['code'], flush=True)
        if expected is not None and entry['code'] != expected:
            raise RuntimeError(json.dumps(entry, default=str))
        return output

    def ready():
        for _ in range(90):
            value = clients['lambda'].get_function_configuration(FunctionName=prefix)
            if value['State'] == 'Active' and value.get('LastUpdateStatus', 'Successful') == 'Successful':
                return
            if value['State'] == 'Failed':
                raise RuntimeError(str(value))
            time.sleep(1)
        raise RuntimeError('Owned function activation timed out')

    messages = []
    def receive(run, kind):
        deadline = time.monotonic() + 120
        while time.monotonic() < deadline:
            for item in clients['sqs'].receive_message(QueueUrl=owned['queue'], WaitTimeSeconds=2, MaxNumberOfMessages=10).get('Messages', []):
                body = json.loads(item['Body'])
                messages.append(body)
                clients['sqs'].delete_message(QueueUrl=owned['queue'], ReceiptHandle=item['ReceiptHandle'])
            for item in messages:
                if item['run'] == run and item['kind'] == kind:
                    return item
        raise RuntimeError('Missing real runtime effect: ' + run + '/' + kind)

    def execution(arn, status):
        for _ in range(90):
            value = clients['lambda'].get_durable_execution(DurableExecutionArn=arn, IncludeExecutionData=True)
            value.pop('ResponseMetadata', None)
            if value['Status'] == status:
                capture['observations'].append({'label': 'terminal_' + status, 'output': value})
                save()
                return value
            if value['Status'] != 'RUNNING':
                raise RuntimeError(str(value))
            time.sleep(1)
        raise RuntimeError('Execution did not reach ' + status)

    try:
        identity = call('identity', 'sts', 'get_caller_identity', {}, expected='Success')
        if not args.endpoint_url and identity['Account'] != args.account:
            raise RuntimeError('Unexpected AWS account; no resources created')
        role = call('create_role', 'iam', 'create_role', {'RoleName': prefix, 'AssumeRolePolicyDocument': json.dumps({'Version': '2012-10-17', 'Statement': [{'Effect': 'Allow', 'Principal': {'Service': 'lambda.amazonaws.com'}, 'Action': 'sts:AssumeRole'}]})}, expected='Success')['Role']['Arn']
        owned['role'] = prefix
        owned['queue'] = call('create_queue', 'sqs', 'create_queue', {'QueueName': prefix}, expected='Success')['QueueUrl']
        statements = [{'Effect': 'Allow', 'Action': ['lambda:CheckpointDurableExecution', 'lambda:GetDurableExecutionState'], 'Resource': '*'}, {'Effect': 'Allow', 'Action': 'sqs:SendMessage', 'Resource': 'arn:aws:sqs:us-east-1:' + identity['Account'] + ':' + prefix}]
        if args.kms_key_arn:
            capture['durable_kms_key_arn'] = args.kms_key_arn
            statements.append({'Effect': 'Allow', 'Action': 'kms:Decrypt', 'Resource': args.kms_key_arn, 'Condition': {'StringEquals': {'kms:ViaService': 'lambda.us-east-1.amazonaws.com', 'kms:EncryptionContext:aws:lambda:FunctionArn': 'arn:aws:lambda:us-east-1:' + identity['Account'] + ':function:' + prefix}}})
            operator_name = prefix + '-operator'
            operator = call('create_operator_role', 'iam', 'create_role', {'RoleName': operator_name, 'AssumeRolePolicyDocument': json.dumps({'Version': '2012-10-17', 'Statement': [{'Effect': 'Allow', 'Principal': {'AWS': identity['Arn']}, 'Action': 'sts:AssumeRole'}]})}, expected='Success')['Role']['Arn']
            owned['operator_role'] = operator_name
            call('operator_policy', 'iam', 'put_role_policy', {'RoleName': operator_name, 'PolicyName': prefix, 'PolicyDocument': json.dumps({'Version': '2012-10-17', 'Statement': [
                {'Effect': 'Allow', 'Action': ['lambda:GetDurableExecution', 'lambda:GetDurableExecutionHistory'], 'Resource': 'arn:aws:lambda:us-east-1:' + identity['Account'] + ':function:' + prefix + '*'},
                {'Effect': 'Deny', 'Action': 'kms:Decrypt', 'Resource': args.kms_key_arn}
            ]})}, expected='Success')
            owned['operator_policy'] = prefix
        call('role_policy', 'iam', 'put_role_policy', {'RoleName': prefix, 'PolicyName': prefix, 'PolicyDocument': json.dumps({'Version': '2012-10-17', 'Statement': statements})}, expected='Success')
        owned['policy'] = prefix
        package = io.BytesIO()
        with zipfile.ZipFile(package, 'w', zipfile.ZIP_DEFLATED) as archive:
            archive.writestr('entry.py', HANDLER)
            for path in sorted(args.sdk_directory.rglob('*')):
                if path.is_file() and '__pycache__' not in path.parts and '.dist-info' not in str(path):
                    archive.write(path, str(path.relative_to(args.sdk_directory)))
        request = {'FunctionName': prefix, 'Role': role, 'Runtime': 'python3.13', 'Handler': 'entry.handler', 'Timeout': 30, 'MemorySize': 128, 'Code': {'ZipFile': package.getvalue()}, 'DurableConfig': {'ExecutionTimeout': 300, 'RetentionPeriodInDays': 1}, 'Publish': True}
        if args.kms_key_arn:
            request['DurableConfig']['KMSKeyArn'] = args.kms_key_arn
        for _ in range(20):
            output = call('create_function', 'lambda', 'create_function', request)
            if output:
                owned['function'] = prefix
                break
            last = capture['observations'][-1]
            if last['code'] != 'InvalidParameterValueException' or 'role' not in last.get('message', '').lower():
                raise RuntimeError(str(last))
            time.sleep(3)
        if 'function' not in owned:
            raise RuntimeError('Role propagation timed out')
        ready()
        for run in ('success', 'failure', 'stop'):
            payload = json.dumps({'queue': owned['queue'], 'run': run}).encode()
            invocation = {'FunctionName': prefix + ':1', 'InvocationType': 'Event', 'DurableExecutionName': prefix + '-' + run, 'Payload': payload}
            accepted = call('invoke_' + run, 'lambda', 'invoke', invocation, expected='Success')
            arn = accepted['DurableExecutionArn']
            owned.setdefault('executions', []).append(arn)
            try:
                callback = receive(run, 'callback')['callback']
            except Exception:
                call('failed_execution_' + run, 'lambda', 'get_durable_execution', {'DurableExecutionArn': arn, 'IncludeExecutionData': True})
                call('failed_history_' + run, 'lambda', 'get_durable_execution_history', {'DurableExecutionArn': arn, 'IncludeExecutionData': True})
                raise
            call('reattach_' + run, 'lambda', 'invoke', invocation, expected='Success')
            changed = dict(invocation, Payload=b'{"changed":true}')
            call('conflict_' + run, 'lambda', 'invoke', changed)
            call('history_running_' + run, 'lambda', 'get_durable_execution_history', {'DurableExecutionArn': arn, 'IncludeExecutionData': True}, expected='Success')
            call('heartbeat_' + run, 'lambda', 'send_durable_execution_callback_heartbeat', {'CallbackId': callback}, expected='Success')
            if run == 'success':
                call('callback_success', 'lambda', 'send_durable_execution_callback_success', {'CallbackId': callback, 'Result': b'{"approved":true}'}, expected='Success')
                receive(run, 'after')
                execution(arn, 'SUCCEEDED')
                if args.kms_key_arn:
                    credentials = clients['sts'].assume_role(RoleArn=operator, RoleSessionName=prefix)['Credentials']
                    clients['operator_lambda'] = boto3.client('lambda', **settings, aws_access_key_id=credentials['AccessKeyId'], aws_secret_access_key=credentials['SecretAccessKey'], aws_session_token=credentials['SessionToken'])
                    for operation in ('get_durable_execution', 'get_durable_execution_history'):
                        for include in (None, False, True):
                            read_request = {'DurableExecutionArn': arn}
                            if include is not None:
                                read_request['IncludeExecutionData'] = include
                            suffix = operation + '_' + str(include)
                            author_output = call('kms_author_' + suffix, 'lambda', operation, read_request, expected='Success')
                            if operation == 'get_durable_execution' and author_output['DurableConfig'].get('KMSKeyArn') != args.kms_key_arn:
                                raise RuntimeError('Execution did not retain its admitted customer key')
                            expected = 'Success' if include is False else 'KMSAccessDeniedException' if include is True else None
                            output = call('kms_denied_operator_' + suffix, 'operator_lambda', operation, read_request, expected=expected)
                            if operation == 'get_durable_execution' and include is False and output.get('ExecutionDataIncluded') is not False:
                                raise RuntimeError('Metadata-only read unexpectedly returned execution data')
                call('callback_success_duplicate', 'lambda', 'send_durable_execution_callback_success', {'CallbackId': callback, 'Result': b'{"approved":true}'})
                call('callback_conflicting_failure', 'lambda', 'send_durable_execution_callback_failure', {'CallbackId': callback, 'Error': {'ErrorType': 'LateFailure'}})
            elif run == 'failure':
                call('callback_failure', 'lambda', 'send_durable_execution_callback_failure', {'CallbackId': callback, 'Error': {'ErrorType': 'ExternalRejected', 'ErrorMessage': 'owned rejection'}}, expected='Success')
                execution(arn, 'FAILED')
            else:
                call('stop', 'lambda', 'stop_durable_execution', {'DurableExecutionArn': arn, 'Error': {'ErrorType': 'OwnedStop', 'ErrorMessage': 'owned stop'}}, expected='Success')
                execution(arn, 'STOPPED')
                call('callback_after_stop', 'lambda', 'send_durable_execution_callback_success', {'CallbackId': callback, 'Result': b'null'})
                call('stop_duplicate', 'lambda', 'stop_durable_execution', {'DurableExecutionArn': arn})
            call('history_terminal_' + run, 'lambda', 'get_durable_execution_history', {'DurableExecutionArn': arn, 'IncludeExecutionData': True}, expected='Success')
        call('list_executions', 'lambda', 'list_durable_executions_by_function', {'FunctionName': prefix, 'MaxItems': 2}, expected='Success')
        capture['effects'] = [{k: v for k, v in message.items() if k != 'callback'} for message in messages]
        counts = {run: sum(m['run'] == run and m['kind'] == 'before' for m in messages) for run in ('success', 'failure', 'stop')}
        if counts != {'success': 1, 'failure': 1, 'stop': 1}:
            raise RuntimeError('Completed checkpoint replay repeated external effect: ' + str(counts))
        capture['ready_for_cleanup'] = True
        save()
        if args.cleanup_gate:
            deadline = time.monotonic() + 1200
            while not args.cleanup_gate.exists() and time.monotonic() < deadline:
                time.sleep(1)
    finally:
        cleanup_errors = []
        for arn in owned.get('executions', []):
            try:
                call('stop_cleanup', 'lambda', 'stop_durable_execution', {'DurableExecutionArn': arn}, True)
            except Exception as error:
                cleanup_errors.append(str(error))
        actions = []
        if 'function' in owned:
            actions.append(('delete_function', 'lambda', 'delete_function', {'FunctionName': prefix}))
        if 'queue' in owned:
            actions.append(('delete_queue', 'sqs', 'delete_queue', {'QueueUrl': owned['queue']}))
        if 'policy' in owned:
            actions.append(('delete_policy', 'iam', 'delete_role_policy', {'RoleName': prefix, 'PolicyName': prefix}))
        if 'role' in owned:
            actions.append(('delete_role', 'iam', 'delete_role', {'RoleName': prefix}))
        if 'operator_policy' in owned:
            actions.append(('delete_operator_policy', 'iam', 'delete_role_policy', {'RoleName': owned['operator_role'], 'PolicyName': prefix}))
        if 'operator_role' in owned:
            actions.append(('delete_operator_role', 'iam', 'delete_role', {'RoleName': owned['operator_role']}))
        for label, service, operation, request in actions:
            try:
                call(label, service, operation, request, True, 'Success')
            except Exception as error:
                cleanup_errors.append(str(error))
        if 'function' in owned:
            for attempt in range(60):
                remaining = call('function_deletion_' + str(attempt), 'lambda', 'get_function_configuration', {'FunctionName': prefix}, True)
                if remaining is None and capture['cleanup'][-1]['code'] == 'ResourceNotFoundException':
                    break
                time.sleep(1)
            else:
                cleanup_errors.append('Owned function deletion did not settle')
        if 'role' in owned:
            call('role_absent', 'iam', 'get_role', {'RoleName': prefix}, True, 'NoSuchEntity')
        save()
        if cleanup_errors:
            raise RuntimeError('; '.join(cleanup_errors))


if __name__ == '__main__':
    main()
