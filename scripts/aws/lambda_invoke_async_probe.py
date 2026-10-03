#!/usr/bin/env python3
"""Owned native legacy InvokeAsync admission, IAM and real SQS side-effect probe."""
import argparse
import base64
import datetime
import io
import json
from pathlib import Path
import time
import uuid
import zipfile
import boto3
from botocore.config import Config
from botocore.exceptions import ClientError


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--account", required=True, help="AWS account ID that STS must match before native writes")
    parser.add_argument("--output", type=Path, default=Path(".stackd/probes/lambda/invoke_async.json"))
    args = parser.parse_args()
    prefix = 'stackd-next-lambda-' + uuid.uuid4().hex[:12]
    session = boto3.Session(region_name='us-east-1')
    identity = session.client('sts').get_caller_identity()
    if identity['Account'] != args.account:
        raise RuntimeError('unexpected native account; no mutation')
    iam, functions, sqs, logs = [session.client(name, config=Config(retries={'total_max_attempts': 1})) for name in ('iam', 'lambda', 'sqs', 'logs')]
    path = args.output
    report = {'source': 'Native AWS signed boto3 public endpoints', 'account': identity['Account'], 'region': 'us-east-1',
              'prefix': prefix, 'started_at': datetime.datetime.now(datetime.timezone.utc).isoformat(), 'observations': [], 'cleanup': {},
              'documentation': ['https://docs.aws.amazon.com/lambda/latest/api/API_InvokeAsync.html']}
    owned = {'role': False, 'function': False, 'queue': None, 'user': False, 'access_key': None}

    def save():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(report, default=str, indent=2) + '\n')

    def observe(label, client, operation, **params):
        try:
            out = getattr(client, operation)(**params)
            result = {'code': 'Success', 'output': out}
        except ClientError as error:
            result = {'code': error.response['Error']['Code'], 'error': error.response['Error'], 'metadata': error.response['ResponseMetadata']}
        report['observations'].append({'label': label, 'operation': operation, 'result': result})
        save()
        print(label + ': ' + result['code'], flush=True)
        return result

    def receive(identifier):
        deadline = time.monotonic() + 90
        while time.monotonic() < deadline:
            for row in sqs.receive_message(QueueUrl=owned['queue'], WaitTimeSeconds=10, MaxNumberOfMessages=10).get('Messages', []):
                sqs.delete_message(QueueUrl=owned['queue'], ReceiptHandle=row['ReceiptHandle'])
                value = json.loads(row['Body'])
                if value['event'].get('id') == identifier:
                    return value
        raise TimeoutError(identifier)

    try:
        owned['queue'] = sqs.create_queue(QueueName=prefix)['QueueUrl']
        queue_arn = sqs.get_queue_attributes(QueueUrl=owned['queue'], AttributeNames=['QueueArn'])['Attributes']['QueueArn']
        role = iam.create_role(RoleName=prefix, AssumeRolePolicyDocument=json.dumps({'Version': '2012-10-17', 'Statement': [
            {'Effect': 'Allow', 'Principal': {'Service': 'lambda.amazonaws.com'}, 'Action': 'sts:AssumeRole'}]}))['Role']['Arn']
        owned['role'] = True
        iam.put_role_policy(RoleName=prefix, PolicyName='owned-queue', PolicyDocument=json.dumps({'Version': '2012-10-17', 'Statement': [
            {'Effect': 'Allow', 'Action': 'sqs:SendMessage', 'Resource': queue_arn}]}))
        package = io.BytesIO()
        with zipfile.ZipFile(package, 'w') as archive:
            archive.writestr('entry.py', "import boto3,json,os\ndef invoke(event,context):\n boto3.client('sqs').send_message(QueueUrl=os.environ['QUEUE'],MessageBody=json.dumps({'event':event,'trace':os.environ.get('_X_AMZN_TRACE_ID'),'version':context.function_version}))\n return event\n")
        for attempt in range(20):
            result = observe('create_function_' + str(attempt), functions, 'create_function', FunctionName=prefix, Role=role,
                Runtime='python3.12', Handler='entry.invoke', Timeout=10, Code={'ZipFile': package.getvalue()}, Environment={'Variables': {'QUEUE': owned['queue']}})
            if result['code'] == 'Success':
                owned['function'] = True
                break
            if result['code'] != 'InvalidParameterValueException':
                raise RuntimeError(result)
            time.sleep(3)
        if not owned['function']:
            raise RuntimeError('function creation did not become ready')
        functions.get_waiter('function_active_v2').wait(FunctionName=prefix)
        functions.publish_version(FunctionName=prefix)
        observe('invoke', functions, 'invoke_async', FunctionName=prefix, InvokeArgs=b'{"id":"normal"}')
        report['normal_effect'] = receive('normal')
        observe('qualified', functions, 'invoke_async', FunctionName=prefix + ':1', InvokeArgs=b'{"id":"qualified"}')
        report['qualified_effect'] = receive('qualified')
        observe('invalid_json', functions, 'invoke_async', FunctionName=prefix, InvokeArgs=b'{')
        observe('over_limit', functions, 'invoke_async', FunctionName=prefix, InvokeArgs=json.dumps({'x': 'x' * (256 * 1024)}).encode())
        iam.create_user(UserName=prefix)
        owned['user'] = True
        key = iam.create_access_key(UserName=prefix)['AccessKey']
        owned['access_key'] = key['AccessKeyId']
        limited = boto3.client('lambda', region_name='us-east-1', aws_access_key_id=key['AccessKeyId'], aws_secret_access_key=key['SecretAccessKey'], config=Config(retries={'total_max_attempts': 1}))
        function_arn = f'arn:aws:lambda:us-east-1:{args.account}:function:' + prefix
        for action in ('InvokeAsync', 'InvokeFunction'):
            iam.put_user_policy(UserName=prefix, PolicyName='only-one-action', PolicyDocument=json.dumps({'Version': '2012-10-17', 'Statement': [
                {'Effect': 'Allow', 'Action': 'lambda:' + action, 'Resource': function_arn}]}))
            time.sleep(15)
            out = observe('authority_' + action, limited, 'invoke_async', FunctionName=prefix, InvokeArgs=json.dumps({'id': action}).encode())
            if out['code'] == 'Success':
                report['authority_effect_' + action] = receive(action)
            save()
    finally:
        if owned['function']:
            functions.delete_function(FunctionName=prefix)
            report['cleanup']['function'] = observe('function_absent', functions, 'get_function', FunctionName=prefix)['code'] == 'ResourceNotFoundException'
        if owned['access_key']:
            iam.delete_access_key(UserName=prefix, AccessKeyId=owned['access_key'])
        if owned['user']:
            for policy in iam.list_user_policies(UserName=prefix)['PolicyNames']:
                iam.delete_user_policy(UserName=prefix, PolicyName=policy)
            iam.delete_user(UserName=prefix)
            report['cleanup']['user'] = True
        if owned['role']:
            iam.delete_role_policy(RoleName=prefix, PolicyName='owned-queue')
            iam.delete_role(RoleName=prefix)
            report['cleanup']['role'] = True
        if owned['queue']:
            sqs.delete_queue(QueueUrl=owned['queue'])
            report['cleanup']['queue'] = True
        try:
            logs.delete_log_group(logGroupName='/aws/lambda/' + prefix)
        except logs.exceptions.ResourceNotFoundException:
            pass
        report['cleanup']['logs'] = True
        save()


if __name__ == '__main__':
    main()
