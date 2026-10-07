#!/usr/bin/env python3
"""Signed real durable SDK/Runtime API/SQS proof with SQLite controller restart."""
import argparse
import base64
import io
import json
import os
from pathlib import Path
import socket
import sqlite3
import subprocess
import sys
import time
import urllib.request
import uuid
import zipfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', required=True)
    parser.add_argument('--sdk-directory', type=Path, required=True)
    parser.add_argument('--state-directory', type=Path, required=True)
    parser.add_argument('--docker-host', default='unix:///var/run/docker.sock')
    parser.add_argument('--telemetry-directory', default='/home/r/dev/minor/stackd/bin')
    parser.add_argument('--scenarios', nargs='+', choices=('restart', 'failure', 'stop'), default=['restart', 'failure', 'stop'])
    parser.add_argument('--cmk', action='store_true')
    args = parser.parse_args()
    sys.path.insert(0, str(args.sdk_directory.resolve()))
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import boto3
    from botocore.config import Config
    from botocore.exceptions import ClientError
    from lambda_durable_probe import HANDLER
    state = args.state_directory.resolve()
    state.mkdir(parents=True, exist_ok=True)
    database = state / 'durable.sqlite'
    if database.exists():
        raise RuntimeError('Fresh owned SQLite state required')
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        port = sock.getsockname()[1]
    endpoint = 'http://127.0.0.1:' + str(port)
    env = {key: value for key, value in os.environ.items() if not key.startswith('AWS_')}
    env['AWS_EC2_METADATA_DISABLED'] = 'true'
    clients = {name: boto3.client(name, endpoint_url=endpoint, region_name='us-east-1', aws_access_key_id='test', aws_secret_access_key='test', config=Config(retries={'total_max_attempts': 1}, read_timeout=180)) for name in ('lambda', 'sqs', 'iam', 'kms', 'sts')}
    prefix = 'durable-proof-' + uuid.uuid4().hex[:10]
    report = {'prefix': prefix, 'observations': {}, 'cleanup': [], 'controllers': []}
    process = log = None
    starts = 0
    owned = {}
    audit_requests = {}

    def wait(fn, label, timeout=120):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            value = fn()
            if value:
                return value
            time.sleep(.2)
        raise RuntimeError('Timed out: ' + label)

    def start():
        nonlocal process, log, starts
        starts += 1
        log = (state / ('controller-' + str(starts) + '.log')).open('wb')
        process = subprocess.Popen([str(Path(args.binary).resolve()), '-listen', '0.0.0.0:' + str(port), '-public-endpoint', endpoint, '-database', str(database), '-docker-host', args.docker_host, '-lambda-runtime', '-lambda-telemetry-directory', args.telemetry_directory, '-compute-endpoint', 'http://host.docker.internal:' + str(port)], env=env, stdout=log, stderr=log)
        def health():
            if process.poll() is not None:
                raise RuntimeError('Controller exited; inspect owned log')
            try:
                with urllib.request.urlopen(endpoint + '/_stackd/health', timeout=1) as response:
                    return response.status == 200
            except OSError:
                return False
        wait(health, 'controller readiness', 180)

    def stop():
        nonlocal process, log
        if process is not None:
            process.terminate()
            status = process.wait(timeout=60)
            report['controllers'].append({'start': starts, 'exit_status': status})
            process = None
            if status != 0:
                raise RuntimeError('Controller failed to close')
        if log is not None:
            log.close()
            log = None

    messages = []
    def collect():
        for message in clients['sqs'].receive_message(QueueUrl=owned['queue'], MaxNumberOfMessages=10, WaitTimeSeconds=1).get('Messages', []):
            body = json.loads(message['Body'])
            messages.append(body)
            clients['sqs'].delete_message(QueueUrl=owned['queue'], ReceiptHandle=message['ReceiptHandle'])
        return messages

    def effect(run, kind):
        return next((message for message in collect() if message.get('run') == run and message['kind'] == kind), None)

    def expect_error(operation, code, **request):
        try:
            getattr(clients['lambda'], operation)(**request)
        except ClientError as error:
            actual = error.response['Error']['Code']
            if actual != code:
                raise RuntimeError('Expected ' + code + ', got ' + actual) from error
            return actual
        raise RuntimeError('Expected rejection ' + code)

    def terminal(arn, wanted):
        value = clients['lambda'].get_durable_execution(DurableExecutionArn=arn, IncludeExecutionData=True)
        if value['Status'] == wanted:
            value.pop('ResponseMetadata', None)
            return value
        if value['Status'] != 'RUNNING':
            raise RuntimeError(json.dumps(value, default=str))
        return None

    try:
        start()
        role = clients['iam'].create_role(RoleName=prefix, AssumeRolePolicyDocument=json.dumps({'Version': '2012-10-17', 'Statement': [{'Effect': 'Allow', 'Principal': {'Service': 'lambda.amazonaws.com'}, 'Action': 'sts:AssumeRole'}]}))['Role']['Arn']
        owned['role'] = prefix
        owned['queue'] = clients['sqs'].create_queue(QueueName=prefix)['QueueUrl']
        account = role.split(':')[4]
        function_arn = 'arn:aws:lambda:us-east-1:' + account + ':function:' + prefix
        durable_config = {'ExecutionTimeout': 300, 'RetentionPeriodInDays': 1}
        policy = [{'Effect': 'Allow', 'Action': ['lambda:CheckpointDurableExecution', 'lambda:GetDurableExecutionState'], 'Resource': function_arn + ':*'}, {'Effect': 'Allow', 'Action': 'sqs:SendMessage', 'Resource': 'arn:aws:sqs:us-east-1:' + account + ':' + prefix}]
        if args.cmk:
            key_policy = {'Version': '2012-10-17', 'Statement': [
                {'Effect': 'Allow', 'Principal': {'AWS': 'arn:aws:iam::' + account + ':root'}, 'Action': 'kms:*', 'Resource': '*'},
                {'Effect': 'Allow', 'Principal': {'Service': 'lambda.amazonaws.com'}, 'Action': ['kms:GenerateDataKey', 'kms:Decrypt'], 'Resource': '*', 'Condition': {'StringEquals': {'aws:SourceAccount': account, 'aws:SourceArn': function_arn, 'kms:EncryptionContext:aws:lambda:FunctionArn': function_arn}}}
            ]}
            owned['key'] = clients['kms'].create_key(Description=prefix, Policy=json.dumps(key_policy))['KeyMetadata']['Arn']
            durable_config['KMSKeyArn'] = owned['key']
            policy.append({'Effect': 'Allow', 'Action': 'kms:Decrypt', 'Resource': owned['key'], 'Condition': {'StringEquals': {'kms:ViaService': 'lambda.us-east-1.amazonaws.com', 'kms:EncryptionContext:aws:lambda:FunctionArn': function_arn}}})
        clients['iam'].put_role_policy(RoleName=prefix, PolicyName=prefix, PolicyDocument=json.dumps({'Version': '2012-10-17', 'Statement': policy}))
        owned['policy'] = prefix
        # Observe real SDK checkpoint responses through its supported boto3 client
        # event hooks. Tokens stay local and never enter the evidence report.
        instrumented = HANDLER.replace('@durable_execution', '''client = boto3.client("lambda")
active_run = active_queue = None

def checkpoint_response(http_response, parsed, **kwargs):
    if active_queue and "CheckpointToken" in parsed:
        sqs.send_message(QueueUrl=active_queue, MessageBody=json.dumps({"kind":"checkpoint", "run":active_run, "token":parsed["CheckpointToken"]}))

client.meta.events.register("after-call.lambda.CheckpointDurableExecution", checkpoint_response)

@durable_execution(boto3_client=client)''').replace('    def emit(kind, extra=None):', '    global active_run, active_queue\n    active_run, active_queue = event["run"], event["queue"]\n    def emit(kind, extra=None):')
        package = io.BytesIO()
        with zipfile.ZipFile(package, 'w', zipfile.ZIP_DEFLATED) as archive:
            archive.writestr('entry.py', instrumented)
            for path in sorted(args.sdk_directory.rglob('*')):
                if path.is_file() and '__pycache__' not in path.parts and '.dist-info' not in str(path):
                    archive.write(path, str(path.relative_to(args.sdk_directory)))
        clients['lambda'].create_function(FunctionName=prefix, Runtime='python3.13', Handler='entry.handler', Role=role, Code={'ZipFile': package.getvalue()}, Timeout=30, MemorySize=128, DurableConfig=durable_config, Publish=True)
        owned['function'] = prefix
        def runtime_ready():
            configuration = clients['lambda'].get_function_configuration(FunctionName=prefix)
            report['last_function_configuration'] = {key: value for key, value in configuration.items() if key != 'ResponseMetadata'}
            if configuration['State'] == 'Failed' or configuration.get('LastUpdateStatus') == 'Failed':
                raise RuntimeError('Runtime activation failed: ' + str(report['last_function_configuration']))
            return configuration['State'] == 'Active'
        wait(runtime_ready, 'runtime activation')
        for run in args.scenarios:
            payload = json.dumps({'run': run, 'queue': owned['queue'].replace('127.0.0.1', 'host.docker.internal')}).encode()
            request = {'FunctionName': prefix + ':1', 'InvocationType': 'Event', 'DurableExecutionName': prefix + '-' + run, 'Payload': payload}
            accepted = clients['lambda'].invoke(**request)
            accepted['Payload'].close()
            arn = accepted['DurableExecutionArn']
            owned.setdefault('executions', []).append(arn)
            callback = wait(lambda: effect(run, 'callback'), run + ' runtime callback')['callback']
            def suspended():
                history = clients['lambda'].get_durable_execution_history(DurableExecutionArn=arn)['Events']
                return history if history[-1]['EventType'] == 'InvocationCompleted' else None
            history = wait(suspended, 'SDK suspension')
            collect()
            token = [message['token'] for message in messages if message.get('run') == run and message['kind'] == 'checkpoint'][-1]
            state_response = clients['lambda'].get_durable_execution_state(DurableExecutionArn=arn, CheckpointToken=token, MaxItems=2)
            if len(state_response['Operations']) != 2 or not state_response.get('NextMarker'):
                raise RuntimeError('State pagination did not return bounded replay state')
            completed = [op for op in clients['lambda'].get_durable_execution_state(DurableExecutionArn=arn, CheckpointToken=token)['Operations'] if op.get('Name') == 'before-effect']
            if len(completed) != 1 or completed[0]['Status'] != 'SUCCEEDED' or completed[0]['StepDetails']['Result'] != '"before"':
                raise RuntimeError('Completed effect checkpoint was not retained')
            checkpoint_request = {'DurableExecutionArn': arn, 'CheckpointToken': token, 'ClientToken': 'owned-' + run, 'Updates': []}
            checkpoint = clients['lambda'].checkpoint_durable_execution(**checkpoint_request)
            if run == 'restart':
                stop()
                start()
            repeated = clients['lambda'].checkpoint_durable_execution(**checkpoint_request)
            if repeated['CheckpointToken'] != checkpoint['CheckpointToken']:
                raise RuntimeError('Idempotent checkpoint changed token across restart')
            stale = expect_error('checkpoint_durable_execution', 'InvalidParameterValueException', **dict(checkpoint_request, ClientToken='different-' + run))
            mismatch = expect_error('checkpoint_durable_execution', 'InvalidParameterValueException', **dict(checkpoint_request, Updates=[{'Id': 'different', 'Type': 'WAIT', 'Action': 'START', 'WaitOptions': {'WaitSeconds': 1}}]))
            clients['lambda'].send_durable_execution_callback_heartbeat(CallbackId=callback)
            if run == 'restart':
                clients['lambda'].send_durable_execution_callback_success(CallbackId=callback, Result=b'{"approved":true}')
                wait(lambda: effect(run, 'after'), 'post-restart external effect')
                value = wait(lambda: terminal(arn, 'SUCCEEDED'), 'durable success')
                duplicate = expect_error('send_durable_execution_callback_success', 'CallbackTimeoutException', CallbackId=callback, Result=b'{"approved":true}')
            elif run == 'failure':
                failed = clients['lambda'].send_durable_execution_callback_failure(CallbackId=callback, Error={'ErrorType': 'ExternalRejected', 'ErrorMessage': 'owned callback rejection'})
                audit_requests[failed['ResponseMetadata']['RequestId']] = ('SendDurableExecutionCallbackFailure', None)
                value = wait(lambda: terminal(arn, 'FAILED'), 'durable failure')
                duplicate = expect_error('send_durable_execution_callback_heartbeat', 'CallbackTimeoutException', CallbackId=callback)
            else:
                stopped = clients['lambda'].stop_durable_execution(DurableExecutionArn=arn, Error={'ErrorType': 'OwnedStop'})
                audit_requests[stopped['ResponseMetadata']['RequestId']] = ('StopDurableExecution', stopped['StopTimestamp'].timestamp())
                value = wait(lambda: terminal(arn, 'STOPPED'), 'durable stop')
                repeated_stop = clients['lambda'].stop_durable_execution(DurableExecutionArn=arn)
                if stopped['StopTimestamp'] != repeated_stop['StopTimestamp']:
                    raise RuntimeError('Repeated stop changed completion time')
                duplicate = expect_error('send_durable_execution_callback_success', 'CallbackTimeoutException', CallbackId=callback, Result=b'null')
            report['observations'][run] = {'execution': value, 'stale_token': stale, 'client_token_conflict': mismatch, 'closed_callback': duplicate, 'checkpoint_idempotence': True}
        collect()
        effects = [{key: value for key, value in message.items() if key != 'callback'} for message in messages if message['kind'] != 'checkpoint']
        report['effects'] = effects
        for run in args.scenarios:
            if sum(message['run'] == run and message['kind'] == 'before' for message in effects) != 1:
                raise RuntimeError('Replay repeated a completed external effect')
            if run != 'restart' and any(message['run'] == run and message['kind'] == 'after' for message in effects):
                raise RuntimeError('Stopped/failed callback resumed external effect')
        report['durable_data_events'] = []
        with sqlite3.connect(database) as connection:
            for request_id, (operation, stopped_at) in audit_requests.items():
                rows = connection.execute('SELECT sequence,event_name,event_category,read_only,request_parameters,response_elements,additional_event_data FROM api_call_events JOIN kernel_events USING(sequence) WHERE request_id=? AND event_source=?', (request_id, 'lambda.amazonaws.com')).fetchall()
                if len(rows) != 1:
                    raise RuntimeError('Durable transition did not commit exactly one API event')
                sequence, name, category, read_only, request, response, additional = rows[0]
                resources = connection.execute('SELECT account_id,resource_type,arn FROM api_call_native_resources WHERE sequence=? ORDER BY position', (sequence,)).fetchall()
                if (name, category, read_only) != (operation, 'Data', 0) or resources != [(account, 'AWS::Lambda::Function', function_arn)]:
                    raise RuntimeError('Durable transition audit classification differs from native delivery')
                if json.loads(request).get('error') != 'HIDDEN_DUE_TO_SECURITY_REASONS' or json.loads(additional).get('functionVersion') != function_arn + ':1':
                    raise RuntimeError('Durable audit leaked errors or lost immutable function identity')
                if stopped_at is not None and abs(json.loads(response)['stopTimestamp'] - stopped_at) > .000001:
                    raise RuntimeError('Stop audit outcome differs from the committed public response')
                report['durable_data_events'].append({'operation': name, 'request_id': request_id, 'category': category, 'resources': resources, 'protected_error': True})
        if args.cmk:
            with sqlite3.connect(database) as connection:
                rows = connection.execute('SELECT key_arn,wrapped_key,encrypted,input,result FROM lambda_durable_executions WHERE function_name=?', (prefix,)).fetchall()
                if len(rows) != len(args.scenarios) or any(key != owned['key'] or not wrapped or encrypted != 1 for key, wrapped, encrypted, _, _ in rows):
                    raise RuntimeError('Execution encryption identity was not durably retained')
                scalars = [value for row in rows for value in row[3:] if value is not None]
                scalars.extend(row[0] for row in connection.execute('SELECT payload FROM lambda_durable_operations WHERE payload IS NOT NULL'))
                scalars.extend(value for row in connection.execute('SELECT error_data,error_message,error_type FROM lambda_durable_errors') for value in row if value is not None)
                scalars.extend(row[0] for row in connection.execute('SELECT frame FROM lambda_durable_error_frames'))
                for value in scalars:
                    raw = base64.b64decode(value + '=' * (-len(value) % 4), validate=True)
                    if len(raw) < 28:
                        raise RuntimeError('A protected durable scalar was persisted without an AEAD envelope')
                for (request,) in connection.execute('SELECT request FROM lambda_durable_checkpoints'):
                    if request is not None and len(request) < 28:
                        raise RuntimeError('Checkpoint idempotency input was persisted without encryption')
            observer_name = prefix + '-observer'
            observer_arn = clients['iam'].create_role(RoleName=observer_name, AssumeRolePolicyDocument=json.dumps({'Version': '2012-10-17', 'Statement': [{'Effect': 'Allow', 'Principal': {'AWS': 'arn:aws:iam::' + account + ':root'}, 'Action': 'sts:AssumeRole'}]}))['Role']['Arn']
            owned['observer_role'] = observer_name
            clients['iam'].put_role_policy(RoleName=observer_name, PolicyName=prefix, PolicyDocument=json.dumps({'Version': '2012-10-17', 'Statement': [{'Effect': 'Allow', 'Action': ['lambda:GetDurableExecution', 'lambda:GetDurableExecutionHistory'], 'Resource': function_arn + ':*'}, {'Effect': 'Deny', 'Action': 'kms:Decrypt', 'Resource': owned['key']}]}))
            owned['observer_policy'] = prefix
            credentials = clients['sts'].assume_role(RoleArn=observer_arn, RoleSessionName='durable-no-decrypt')['Credentials']
            observer = boto3.client('lambda', endpoint_url=endpoint, region_name='us-east-1', aws_access_key_id=credentials['AccessKeyId'], aws_secret_access_key=credentials['SecretAccessKey'], aws_session_token=credentials['SessionToken'], config=Config(retries={'total_max_attempts': 1}))
            arn = owned['executions'][0]
            metadata = observer.get_durable_execution(DurableExecutionArn=arn, IncludeExecutionData=False)
            if metadata['ExecutionDataIncluded'] or metadata['DurableConfig']['KMSKeyArn'] != owned['key'] or 'InputPayload' in metadata:
                raise RuntimeError('Metadata-only read exposed data or lost the immutable execution key')
            metadata_histories = []
            for selection in ({}, {'IncludeExecutionData': False}):
                history = observer.get_durable_execution_history(DurableExecutionArn=arn, **selection)
                wrappers = [detail[key] for event in history['Events'] for detail in event.values() if isinstance(detail, dict) for key in ('Input', 'Result', 'Error') if key in detail]
                if not wrappers or any(wrapper.get('Truncated') is not True or 'Payload' in wrapper for wrapper in wrappers):
                    raise RuntimeError('History metadata default exposed payload or lost native truncation')
                metadata_histories.append('omitted' if not selection else 'false')
            denied_reads = []
            for method, selection in (('get_durable_execution', {}), ('get_durable_execution', {'IncludeExecutionData': True}), ('get_durable_execution_history', {'IncludeExecutionData': True})):
                try:
                    getattr(observer, method)(DurableExecutionArn=arn, **selection)
                except ClientError as error:
                    if error.response['Error']['Code'] != 'KMSAccessDeniedException':
                        raise
                    denied_reads.append({'operation': method, 'selection': 'true' if selection else 'omitted', 'code': error.response['Error']['Code'], 'http_status': error.response['ResponseMetadata']['HTTPStatusCode']})
                else:
                    raise RuntimeError('Payload read bypassed current caller KMS denial')
            report['cmk'] = {'key_arn': owned['key'], 'encrypted_typed_scalars': len(scalars), 'metadata_without_decrypt': True, 'history_metadata_selections': metadata_histories, 'caller_fas_decrypt_denied': denied_reads}
            if any(read['http_status'] != 502 for read in denied_reads):
                raise RuntimeError('Durable payload KMS rejection must use Lambda HTTP 502: ' + json.dumps(denied_reads))
        print('PASS: signed durable SDK checkpoints, exact external effects, scenarios=' + ','.join(args.scenarios), flush=True)
    except Exception as error:
        report['failure'] = str(error)
        if process is not None and 'function' in owned:
            try:
                report['last_function_configuration'] = {key: value for key, value in clients['lambda'].get_function_configuration(FunctionName=prefix).items() if key != 'ResponseMetadata'}
                for arn in owned.get('executions', []):
                    report.setdefault('failed_execution_metadata', []).append({key: value for key, value in clients['lambda'].get_durable_execution(DurableExecutionArn=arn, IncludeExecutionData=False).items() if key != 'ResponseMetadata'})
            except Exception as diagnostic_error:
                report['diagnostic_error'] = str(diagnostic_error)
        raise
    finally:
        cleanup_errors = []
        actions = []
        if process is not None:
            for arn in owned.get('executions', []):
                actions.append(('execution', 'lambda', 'stop_durable_execution', {'DurableExecutionArn': arn}))
            if 'function' in owned:
                actions.append(('function', 'lambda', 'delete_function', {'FunctionName': prefix}))
            if 'queue' in owned:
                actions.append(('queue', 'sqs', 'delete_queue', {'QueueUrl': owned['queue']}))
            if 'policy' in owned:
                actions.append(('policy', 'iam', 'delete_role_policy', {'RoleName': prefix, 'PolicyName': prefix}))
            if 'role' in owned:
                actions.append(('role', 'iam', 'delete_role', {'RoleName': prefix}))
            if 'observer_policy' in owned:
                actions.append(('observer_policy', 'iam', 'delete_role_policy', {'RoleName': owned['observer_role'], 'PolicyName': owned['observer_policy']}))
            if 'observer_role' in owned:
                actions.append(('observer_role', 'iam', 'delete_role', {'RoleName': owned['observer_role']}))
            if 'key' in owned:
                actions.append(('disable_key', 'kms', 'disable_key', {'KeyId': owned['key']}))
                actions.append(('key_pending_deletion', 'kms', 'schedule_key_deletion', {'KeyId': owned['key'], 'PendingWindowInDays': 7}))
        for label, service, operation, request in actions:
            try:
                if label == 'execution' and clients['lambda'].get_durable_execution(DurableExecutionArn=request['DurableExecutionArn'], IncludeExecutionData=False)['Status'] != 'RUNNING':
                    continue
                getattr(clients[service], operation)(**request)
                report['cleanup'].append(label)
            except Exception as error:
                cleanup_errors.append(operation + ': ' + str(error))
        try:
            stop()
        except Exception as error:
            cleanup_errors.append('controller shutdown: ' + str(error))
        report['cleanup_errors'] = cleanup_errors
        (state / 'report.json').write_text(json.dumps(report, indent=2, default=str) + '\n')
        if cleanup_errors:
            raise RuntimeError('; '.join(cleanup_errors))


if __name__ == '__main__':
    main()
