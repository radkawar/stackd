#!/usr/bin/env python3
"""Capture exact-owned durable audit and optional customer-KMS workflow evidence."""
import argparse
import datetime
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import uuid
import zipfile


def redact(value):
    if isinstance(value, dict):
        secret = {'checkpointtoken', 'callbackid', 'accesskeyid', 'payload', 'result', 'errordata', 'errormessage', 'stacktrace', 'inputpayload', 'location', 'ciphertextblob', 'plaintext'}
        return {key: '<redacted>' if key.lower() in secret else redact(item) for key, item in value.items()}
    if isinstance(value, list):
        return [redact(item) for item in value]
    return value


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--account", required=True, help="AWS account ID that STS must match before native writes")
    parser.add_argument('--sdk-directory', type=Path, required=True)
    parser.add_argument('--output', type=Path, default=Path('.stackd/probes/lambda/durable_audit_confirmed.json'))
    parser.add_argument('--with-kms', action='store_true')
    args = parser.parse_args()
    sys.path.insert(0, str(args.sdk_directory.resolve()))
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import boto3
    from botocore.exceptions import ClientError
    from cloudtrail_events import collect_s3
    clients = {name: boto3.client(name, region_name='us-east-1') for name in ('sts', 's3', 'cloudtrail', 'iam', 'lambda', 'kms', 'logs')}
    identity = clients['sts'].get_caller_identity()
    if identity['Account'] != args.account:
        raise RuntimeError('Unexpected native account; no resources created')
    prefix = 'stackd-next-durable-' + uuid.uuid4().hex[:10]
    bucket = prefix + '-audit'
    control = prefix + '-control'
    trail_arn = 'arn:aws:cloudtrail:us-east-1:' + identity['Account'] + ':trail/' + prefix
    function_prefix = 'arn:aws:lambda:us-east-1:' + identity['Account'] + ':function:' + prefix
    report = {'prefix': prefix, 'account': identity['Account'], 'started_at': datetime.datetime.now(datetime.timezone.utc).isoformat(), 'events': [], 'cleanup': []}
    owned = set()
    process = None
    key_arn = None
    scratch = tempfile.TemporaryDirectory(prefix='lambda-durable-audit-')
    gate = Path(scratch.name) / 'cleanup-ready'
    def save():
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(redact(report), indent=2, default=str) + '\n')
    try:
        clients['s3'].create_bucket(Bucket=bucket)
        owned.add('bucket')
        clients['s3'].put_bucket_policy(Bucket=bucket, Policy=json.dumps({'Version': '2012-10-17', 'Statement': [
            {'Effect': 'Allow', 'Principal': {'Service': 'cloudtrail.amazonaws.com'}, 'Action': 's3:GetBucketAcl', 'Resource': 'arn:aws:s3:::' + bucket, 'Condition': {'StringEquals': {'aws:SourceArn': trail_arn}}},
            {'Effect': 'Allow', 'Principal': {'Service': 'cloudtrail.amazonaws.com'}, 'Action': 's3:PutObject', 'Resource': 'arn:aws:s3:::' + bucket + '/AWSLogs/' + identity['Account'] + '/*', 'Condition': {'StringEquals': {'aws:SourceArn': trail_arn, 's3:x-amz-acl': 'bucket-owner-full-control'}}}
        ]}))
        clients['cloudtrail'].create_trail(Name=prefix, S3BucketName=bucket, IsMultiRegionTrail=False, IncludeGlobalServiceEvents=False)
        owned.add('trail')
        clients['cloudtrail'].put_event_selectors(TrailName=prefix, AdvancedEventSelectors=[
            {'Name': 'owned-durable-data', 'FieldSelectors': [{'Field': 'eventCategory', 'Equals': ['Data']}, {'Field': 'resources.type', 'Equals': ['AWS::Lambda::Function']}, {'Field': 'resources.ARN', 'StartsWith': [function_prefix]}]},
            {'Name': 'management', 'FieldSelectors': [{'Field': 'eventCategory', 'Equals': ['Management']}]},
        ])
        clients['cloudtrail'].start_logging(Name=prefix)
        report['selectors'] = clients['cloudtrail'].get_event_selectors(TrailName=prefix)
        report['status_before_propagation'] = clients['cloudtrail'].get_trail_status(Name=prefix)
        role = clients['iam'].create_role(RoleName=control, AssumeRolePolicyDocument=json.dumps({'Version': '2012-10-17', 'Statement': [{'Effect': 'Allow', 'Principal': {'Service': 'lambda.amazonaws.com'}, 'Action': 'sts:AssumeRole'}]}))['Role']['Arn']
        owned.add('control_role')
        if args.with_kms:
            policy = {'Version': '2012-10-17', 'Statement': [
                {'Sid': 'OwnedAdministrator', 'Effect': 'Allow', 'Principal': {'AWS': 'arn:aws:iam::' + identity['Account'] + ':root'}, 'Action': 'kms:*', 'Resource': '*'},
                {'Sid': 'OwnedLambdaDurableService', 'Effect': 'Allow', 'Principal': {'Service': 'lambda.amazonaws.com'}, 'Action': ['kms:GenerateDataKey', 'kms:Decrypt'], 'Resource': '*', 'Condition': {'StringEquals': {
                    'aws:SourceAccount': identity['Account'], 'aws:SourceArn': function_prefix,
                    'kms:EncryptionContext:aws:lambda:FunctionArn': function_prefix
                }}}
            ]}
            key_arn = clients['kms'].create_key(Description=prefix, Policy=json.dumps(policy), Tags=[{'TagKey': 'stackd-owned-probe', 'TagValue': prefix}])['KeyMetadata']['Arn']
            report['durable_kms_key_arn'] = key_arn
            report['kms_reference'] = 'https://docs.aws.amazon.com/lambda/latest/dg/durable-encryption.html'
        save()
        time.sleep(300)
        package = io.BytesIO()
        with zipfile.ZipFile(package, 'w', zipfile.ZIP_DEFLATED) as archive:
            archive.writestr('entry.py', 'def handler(event, context):\n    return {"owned_audit_control": True}\n')
        clients['lambda'].create_function(FunctionName=control, Role=role, Runtime='python3.13', Handler='entry.handler', Timeout=10, MemorySize=128, Code={'ZipFile': package.getvalue()})
        owned.add('control_function')
        clients['lambda'].get_waiter('function_active_v2').wait(FunctionName=control)
        result = None
        request_ids = {}
        control_delivered = False
        for attempt in range(20):
            response = clients['lambda'].invoke(FunctionName=control, Payload=b'{}')
            response['Payload'].read()
            request_ids[response['ResponseMetadata']['RequestId']] = 'owned_control_' + str(attempt)
            result = collect_s3(lambda request: clients['s3'].list_objects_v2(**request), lambda request: clients['s3'].get_object(**request), request_ids, bucket=bucket, rounds=1, max_pages=10, related=lambda event: function_prefix in json.dumps(event), previous=result)
            report['control_collection'] = result
            report['status_after_control'] = clients['cloudtrail'].get_trail_status(Name=prefix)
            control_delivered = any(entry['event'].get('eventName') == 'Invoke' for entry in result['events'])
            save()
            print('owned native Invoke delivery ' + str(attempt) + ': ' + str(control_delivered), flush=True)
            if control_delivered:
                break
            time.sleep(30)
        report['control_delivery_proven'] = control_delivered
        if not control_delivered:
            raise RuntimeError('Native trail never delivered the owned Invoke control within the bounded window')
        workflow = args.output.with_name(args.output.stem + '_workflow.json')
        command = [sys.executable, '-B', '-P', str(Path(__file__).with_name('lambda_durable_probe.py')), '--account', args.account, '--sdk-directory', str(args.sdk_directory), '--prefix', prefix, '--cleanup-gate', str(gate), '--output', str(workflow)]
        if key_arn:
            command += ['--kms-key-arn', key_arn]
        process = subprocess.Popen(command)
        deadline = time.monotonic() + 300
        while time.monotonic() < deadline:
            if process.poll() is not None:
                raise RuntimeError('Native workflow exited before retained audit capture: ' + str(process.returncode))
            if workflow.exists():
                try:
                    workflow_data = json.loads(workflow.read_text())
                except json.JSONDecodeError:
                    workflow_data = {}
                if workflow_data.get('ready_for_cleanup'):
                    break
            time.sleep(1)
        else:
            raise RuntimeError('Native workflow did not reach audit capture boundary')
        request_ids.update({entry['request_id']: entry['label'] for entry in workflow_data['observations'] if entry.get('request_id')})
        required = {'stop', 'callback_failure'}
        for attempt in range(30):
            result = collect_s3(lambda request: clients['s3'].list_objects_v2(**request), lambda request: clients['s3'].get_object(**request), request_ids, bucket=bucket, rounds=1, max_pages=10, related=lambda event: function_prefix in json.dumps(event), previous=result)
            report['collection'] = result
            report['events'] = [entry['event'] for entry in result['events']]
            report['observed_event_names'] = sorted({event['eventName'] for event in report['events']})
            delivered = {entry['call_label'] for entry in result['events']}
            report['targeted_classification'] = {entry['call_label']: entry['event'] for entry in result['events'] if entry['call_label'] in required}
            save()
            print('durable audit delivery ' + str(attempt) + ': ' + ','.join(report['observed_event_names']), flush=True)
            if required.issubset(delivered):
                break
            time.sleep(30)
        report['unobserved_calls_within_bound'] = sorted(required - delivered)
    finally:
        failures = []
        if process is not None:
            gate.touch()
            try:
                if process.wait(timeout=180) != 0:
                    failures.append('durable workflow failed; inspect exact-owned cleanup evidence')
            except Exception as error:
                failures.append(str(error))
        if 'control_function' in owned:
            try:
                clients['lambda'].delete_function(FunctionName=control)
                report['cleanup'].append('delete_control_function')
            except Exception as error:
                failures.append(str(error))
        if 'control_role' in owned:
            try:
                clients['iam'].delete_role(RoleName=control)
                report['cleanup'].append('delete_control_role')
            except Exception as error:
                failures.append(str(error))
        if 'trail' in owned:
            for operation in ('stop_logging', 'delete_trail'):
                try:
                    getattr(clients['cloudtrail'], operation)(Name=prefix)
                    report['cleanup'].append(operation)
                except Exception as error:
                    failures.append(str(error))
        if 'bucket' in owned:
            try:
                for page in clients['s3'].get_paginator('list_objects_v2').paginate(Bucket=bucket):
                    objects = [{'Key': row['Key']} for row in page.get('Contents', [])]
                    if objects:
                        clients['s3'].delete_objects(Bucket=bucket, Delete={'Objects': objects})
                clients['s3'].delete_bucket(Bucket=bucket)
                report['cleanup'].append('delete_bucket')
            except Exception as error:
                failures.append(str(error))
        if key_arn is not None:
            try:
                clients['kms'].disable_key(KeyId=key_arn)
                report['cleanup'].append({'operation': 'disable_key', 'key_arn': key_arn})
                deletion = clients['kms'].schedule_key_deletion(KeyId=key_arn, PendingWindowInDays=7)
                report['cleanup'].append({'operation': 'schedule_key_deletion', 'key_arn': key_arn, 'key_state': deletion['KeyState'], 'deletion_date': deletion['DeletionDate'], 'pending_window_days': deletion['PendingWindowInDays']})
                report['retained_by_aws'] = 'The exact-owned KMS key is disabled and PendingDeletion for the required seven-day window.'
            except Exception as error:
                failures.append(str(error))
        for name in (prefix, control):
            group = '/aws/lambda/' + name
            try:
                response = clients['logs'].delete_log_group(logGroupName=group)
                report['cleanup'].append({'operation': 'delete_log_group', 'log_group': group, 'code': 'Success', 'request_id': response['ResponseMetadata']['RequestId']})
            except ClientError as error:
                code = error.response['Error']['Code']
                report['cleanup'].append({'operation': 'delete_log_group', 'log_group': group, 'code': code, 'request_id': error.response['ResponseMetadata']['RequestId']})
                if code != 'ResourceNotFoundException':
                    failures.append(str(error))
        scratch.cleanup()
        save()
        if failures:
            raise RuntimeError('; '.join(failures))


if __name__ == '__main__':
    main()
