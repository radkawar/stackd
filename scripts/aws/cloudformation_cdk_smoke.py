#!/usr/bin/env python3
"""Local-only unmodified AWS CDK bootstrap/deploy/update/rollback/destroy proof.

Requires a built stackd, Node.js, aws-cdk, aws-cdk-lib, constructs, boto3 and
openssl. Install the official packages together, then pass --cdk and --node-path.
No host AWS credentials are used. The default synthesizer and bootstrap template
are unchanged; CDK telemetry is disabled through its documented application flag.
"""
import argparse
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import time
import uuid

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

from stackd_process import StackdProcess


APP = r'''const cdk = require('aws-cdk-lib');
const s3 = require('aws-cdk-lib/aws-s3');
const sqs = require('aws-cdk-lib/aws-sqs');
const ssm = require('aws-cdk-lib/aws-ssm');
const assets = require('aws-cdk-lib/aws-s3-assets');
const app = new cdk.App({analyticsReporting:false});
const stack = new cdk.Stack(app, process.env.PROOF_STACK, {
  env:{account:process.env.CDK_DEFAULT_ACCOUNT,region:process.env.CDK_DEFAULT_REGION}
});
const stage = process.env.PROOF_STAGE || 'create';
const bucket = new s3.Bucket(stack,'Data',{removalPolicy:cdk.RemovalPolicy.DESTROY});
const queue = new sqs.Queue(stack,'Messages',{
  queueName:process.env.PROOF_STACK + (stage === 'create' || stage === 'update' ? '-first' : '-replacement'),
  visibilityTimeout:cdk.Duration.seconds(stage === 'create' ? 30 : 47),
  removalPolicy:cdk.RemovalPolicy.DESTROY
});
const asset = new assets.Asset(stack,'PublishedFile',{path:'payload.txt'});
const parameter = new ssm.StringParameter(stack,'Stage',{
  parameterName:'/'+process.env.PROOF_STACK+'/stage',stringValue:stage === 'rollback' ? 'must-be-rolled-back' : stage
});
if(stage === 'rollback'){
  const fail = new sqs.CfnQueue(stack,'Failure',{
    queueName:process.env.PROOF_STACK+'-failure',
    redrivePolicy:{deadLetterTargetArn:`arn:aws:sqs:${stack.region}:${stack.account}:${process.env.PROOF_STACK}-absent`,maxReceiveCount:3}
  });
  fail.addDependency(parameter.node.defaultChild);
}
new cdk.CfnOutput(stack,'Bucket',{value:bucket.bucketName});
new cdk.CfnOutput(stack,'Queue',{value:queue.queueUrl});
new cdk.CfnOutput(stack,'Parameter',{value:parameter.parameterName});
new cdk.CfnOutput(stack,'AssetBucket',{value:asset.s3BucketName});
new cdk.CfnOutput(stack,'AssetKey',{value:asset.s3ObjectKey});
'''


def require(value, message):
    if not value:
        raise AssertionError(message)


class Proof:
    def __init__(self, args):
        self.args = args
        self.state = Path(args.state_directory).resolve()
        self.state.mkdir(parents=True, exist_ok=True)
        require(not any(self.state.iterdir()), 'state directory must be empty and exact-owned')
        self.name = 'cdk-proof-' + uuid.uuid4().hex[:10]
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0))
            self.port = sock.getsockname()[1]
        self.endpoint = f'https://127.0.0.1:{self.port}'
        self.cert = self.state / 'certificate.pem'
        self.key = self.state / 'key.pem'
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                        '-subj', '/CN=localhost', '-addext', 'subjectAltName=IP:127.0.0.1,DNS:localhost',
                        '-keyout', str(self.key), '-out', str(self.cert)], check=True, capture_output=True)
        self.env = {k: v for k, v in os.environ.items() if not k.startswith(('AWS_', 'CDK_'))}
        self.env.update(AWS_ACCESS_KEY_ID='test', AWS_SECRET_ACCESS_KEY='test', AWS_DEFAULT_REGION='us-east-1',
                        AWS_REGION='us-east-1', AWS_EC2_METADATA_DISABLED='true', AWS_ENDPOINT_URL=self.endpoint,
                        AWS_CONFIG_FILE=str(self.state / 'aws-config'), AWS_SHARED_CREDENTIALS_FILE=os.devnull,
                        AWS_CA_BUNDLE=str(self.cert), NODE_EXTRA_CA_CERTS=str(self.cert), AWS_MAX_ATTEMPTS='1',
                        CDK_S3_FORCE_PATH_STYLE='true', CDK_DISABLE_VERSION_CHECK='1',
                        AWS_ENDPOINT_URL_S3_FOR_CLOUDFORMATION='https://s3.us-east-1.amazonaws.com',
                        CDK_DEFAULT_ACCOUNT='000000000000', CDK_DEFAULT_REGION='us-east-1',
                        NODE_PATH=str(Path(args.node_path).resolve()), PROOF_STACK=self.name, AWS_PAGER='')
        (self.state / 'aws-config').write_text('[default]\nregion = us-east-1\nendpoint_url = ' + self.endpoint +
                                              '\ns3 =\n  addressing_style = path\n')
        (self.state / 'app.js').write_text(APP)
        (self.state / 'cdk.json').write_text(json.dumps({'app': 'node app.js'}))
        (self.state / 'payload.txt').write_text('ordinary CDK file asset: ' + self.name + '\n')
        self.clients = {name: boto3.client(name, endpoint_url=self.endpoint, region_name='us-east-1',
            aws_access_key_id='test', aws_secret_access_key='test', verify=str(self.cert),
            config=Config(retries={'max_attempts': 0}, s3={'addressing_style': 'path'}))
            for name in ('cloudformation', 's3', 'sqs', 'ssm', 'iam', 'ecr')}
        self.controller = StackdProcess(self.state)
        self.report = {'stack': self.name, 'endpoint': self.endpoint, 'commands': [], 'observations': {}, 'controllers': self.controller.runs, 'cleanup': {}}
        self.bootstrap_resources = {}
        self.app_resources = {}

    def save(self):
        (self.state / 'report.json').write_text(json.dumps(self.report, indent=2, default=str) + '\n')

    def start(self):
        command = [str(Path(self.args.binary).resolve()), '-listen', f'127.0.0.1:{self.port}',
            '-public-endpoint', self.endpoint, '-database', str(self.state / 'state.sqlite'),
            '-tls-cert', str(self.cert), '-tls-key', str(self.key)]
        context = ssl.create_default_context(cafile=str(self.cert))
        self.controller.start(command, self.endpoint, environment=self.env, timeout=180, tls=context)

    def wait(self, callback, label, timeout=180):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            value = callback()
            if value:
                return value
            time.sleep(0.2)
        raise TimeoutError(label)

    def cdk(self, *args, stage='create', success=True):
        env = dict(self.env, PROOF_STAGE=stage)
        result = subprocess.run([str(Path(self.args.cdk).resolve()), *args, '--notices', 'false'], cwd=self.state,
                                env=env, capture_output=True, text=True, timeout=360)
        self.report['commands'].append({'argv': ['cdk', *args, '--notices', 'false'], 'stage': stage, 'exit': result.returncode,
                                       'stdout': result.stdout, 'stderr': result.stderr})
        self.save()
        require((result.returncode == 0) == success, 'CDK command outcome: ' + result.stdout + result.stderr)
        return result

    def stack(self, name):
        return self.clients['cloudformation'].describe_stacks(StackName=name)['Stacks'][0]

    def outputs(self):
        return {v['OutputKey']: v['OutputValue'] for v in self.stack(self.name).get('Outputs', [])}

    def resources(self, name):
        return {v['LogicalResourceId']: v for v in self.clients['cloudformation'].list_stack_resources(StackName=name)['StackResourceSummaries']}

    def error(self, operation, codes, **kwargs):
        try:
            operation(**kwargs)
        except ClientError as error:
            code = error.response['Error']['Code']
            require(code in codes, f'expected {codes}, got {error}')
            return code
        raise AssertionError('expected resource absence')

    def data_path(self, stage):
        out = self.outputs()
        c = self.clients
        expected = (self.state / 'payload.txt').read_bytes()
        actual = c['s3'].get_object(Bucket=out['AssetBucket'], Key=out['AssetKey'])['Body'].read()
        require(actual == expected, 'CDK published file asset bytes differ')
        marker = self.name + '-' + stage
        c['s3'].put_object(Bucket=out['Bucket'], Key='proof', Body=marker.encode())
        body = c['s3'].get_object(Bucket=out['Bucket'], Key='proof')['Body'].read().decode()
        require(body == marker, 'provisioned S3 data path failed')
        c['sqs'].send_message(QueueUrl=out['Queue'], MessageBody=body)
        received = c['sqs'].receive_message(QueueUrl=out['Queue'], WaitTimeSeconds=1)['Messages'][0]
        require(received['Body'] == marker, 'provisioned SQS data path failed')
        c['sqs'].delete_message(QueueUrl=out['Queue'], ReceiptHandle=received['ReceiptHandle'])
        value = c['ssm'].get_parameter(Name=out['Parameter'])['Parameter']['Value']
        require(value == stage, 'provisioned SSM value differs from deployed stage')
        self.report['observations'][stage] = {'queue': out['Queue'], 'bucket': out['Bucket'], 'parameter': value, 'asset_bytes': len(actual)}
        return out

    def empty_bucket(self, name):
        s3 = self.clients['s3']
        for page in s3.get_paginator('list_object_versions').paginate(Bucket=name):
            objects = [{'Key': v['Key'], 'VersionId': v['VersionId']} for field in ('Versions', 'DeleteMarkers') for v in page.get(field, [])]
            if objects:
                s3.delete_objects(Bucket=name, Delete={'Objects': objects})
        for page in s3.get_paginator('list_objects_v2').paginate(Bucket=name):
            for obj in page.get('Contents', []):
                s3.delete_object(Bucket=name, Key=obj['Key'])

    def absent(self, resources):
        for logical, row in resources.items():
            ident, kind = row.get('PhysicalResourceId'), row['ResourceType']
            if not ident or row['ResourceStatus'] == 'CREATE_FAILED':
                continue
            if kind == 'AWS::SQS::Queue':
                code = self.error(self.clients['sqs'].get_queue_attributes, ['AWS.SimpleQueueService.NonExistentQueue'], QueueUrl=ident, AttributeNames=['QueueArn'])
            elif kind == 'AWS::S3::Bucket':
                code = self.error(self.clients['s3'].head_bucket, ['404'], Bucket=ident)
            elif kind == 'AWS::SSM::Parameter':
                code = self.error(self.clients['ssm'].get_parameter, ['ParameterNotFound'], Name=ident)
            elif kind == 'AWS::ECR::Repository':
                code = self.error(self.clients['ecr'].describe_repositories, ['RepositoryNotFoundException'], repositoryNames=[ident])
            elif kind == 'AWS::IAM::Role':
                code = self.error(self.clients['iam'].get_role, ['NoSuchEntity'], RoleName=ident)
            elif kind in ('AWS::S3::BucketPolicy', 'AWS::IAM::Policy'):
                continue  # Absence of parent bucket/role proves attached policy absence.
            else:
                raise AssertionError('missing absence check for ' + kind)
            self.report['cleanup'][logical] = code

    def run(self):
        self.start()
        self.cdk('--version')
        # The current official bootstrap command selects the AWS-managed S3 key.
        # No template substitution, bootstrap bypass or synthesized-template rewrite.
        self.cdk('bootstrap', 'aws://000000000000/us-east-1')
        boot = self.stack('CDKToolkit')
        require(boot['StackStatus'] in ('CREATE_COMPLETE', 'UPDATE_COMPLETE'), 'bootstrap did not complete')
        self.bootstrap_resources = self.resources('CDKToolkit')
        self.cdk('deploy', self.name, '--require-approval', 'never')
        self.app_resources = self.resources(self.name)
        first = self.data_path('create')
        self.cdk('deploy', self.name, '--require-approval', 'never', stage='update')
        updated = self.data_path('update')
        require(updated['Queue'] == first['Queue'], 'mutable update replaced queue')
        attrs = self.clients['sqs'].get_queue_attributes(QueueUrl=updated['Queue'], AttributeNames=['VisibilityTimeout'])['Attributes']
        require(attrs['VisibilityTimeout'] == '47', 'owner did not apply mutable queue update')
        self.cdk('deploy', self.name, '--require-approval', 'never', stage='replacement')
        replaced = self.data_path('replacement')
        require(replaced['Queue'] != first['Queue'], 'create-only queue change did not replace')
        self.error(self.clients['sqs'].get_queue_attributes, ['AWS.SimpleQueueService.NonExistentQueue'], QueueUrl=first['Queue'], AttributeNames=['QueueArn'])
        self.app_resources = self.resources(self.name)
        self.cdk('deploy', self.name, '--require-approval', 'never', stage='rollback', success=False)
        require(self.stack(self.name)['StackStatus'] == 'UPDATE_ROLLBACK_COMPLETE', 'failed CDK update did not roll back')
        events = self.clients['cloudformation'].describe_stack_events(StackName=self.name)['StackEvents']
        require(any(v['ResourceStatus'] == 'CREATE_FAILED' and v['LogicalResourceId'] == 'Failure' for v in events), 'rollback was not caused by the actual owner failure')
        self.data_path('replacement')
        self.error(self.clients['sqs'].get_queue_url, ['AWS.SimpleQueueService.NonExistentQueue'], QueueName=self.name + '-failure')
        self.report['observations']['rollback'] = {'status': 'UPDATE_ROLLBACK_COMPLETE', 'failed_resource': 'Failure'}
        identity = self.stack(self.name)['StackId']
        pending = self.name + '-restart-pending'
        self.clients['sqs'].send_message(QueueUrl=replaced['Queue'], MessageBody=pending)
        self.controller.stop()
        self.start()
        require(self.stack(self.name)['StackId'] == identity, 'stack identity changed on restart')
        retained = self.clients['s3'].get_object(Bucket=replaced['Bucket'], Key='proof')['Body'].read().decode()
        require(retained == self.name + '-replacement', 'provisioned S3 bytes were lost on restart')
        message = self.clients['sqs'].receive_message(QueueUrl=replaced['Queue'], WaitTimeSeconds=1)['Messages'][0]
        require(message['Body'] == pending, 'provisioned SQS message was lost on restart')
        self.clients['sqs'].delete_message(QueueUrl=replaced['Queue'], ReceiptHandle=message['ReceiptHandle'])
        self.data_path('replacement')
        self.report['observations']['restart'] = {'stack_id': identity, 'resolved_parameters': self.stack(self.name)['Parameters'],
                                                'retained_s3_body': retained, 'retained_sqs_body': message['Body']}
        self.empty_bucket(replaced['Bucket'])
        self.cdk('destroy', self.name, '--force', stage='replacement')
        self.error(self.clients['cloudformation'].describe_stacks, ['ValidationError'], StackName=self.name)
        self.absent(self.app_resources)
        # CDK does not synthesize its bootstrap stack as an app. Delete through
        # CloudFormation, respecting the official template's retained asset bucket.
        self.remove_bootstrap()
        self.report['complete'] = True

    def remove_bootstrap(self):
        if not self.bootstrap_resources:
            try:
                self.bootstrap_resources = self.resources('CDKToolkit')
            except ClientError:
                return
        stack = self.stack('CDKToolkit')
        self.clients['cloudformation'].delete_stack(StackName=stack['StackId'])
        self.wait(lambda: self.stack(stack['StackId'])['StackStatus'] == 'DELETE_COMPLETE', 'bootstrap deletion')
        for row in self.bootstrap_resources.values():
            if row['ResourceType'] == 'AWS::S3::Bucket' and row.get('PhysicalResourceId'):
                self.empty_bucket(row['PhysicalResourceId'])
                self.clients['s3'].delete_bucket(Bucket=row['PhysicalResourceId'])
        self.absent(self.bootstrap_resources)
        self.bootstrap_resources = {}

    def cleanup(self):
        failures = []
        if self.controller.process is not None:
            try:
                try:
                    stack = self.stack(self.name)
                except ClientError:
                    stack = None
                if stack:
                    resources = self.resources(self.name)
                    for row in resources.values():
                        if row['ResourceType'] == 'AWS::S3::Bucket' and row.get('PhysicalResourceId'):
                            self.empty_bucket(row['PhysicalResourceId'])
                    self.clients['cloudformation'].delete_stack(StackName=stack['StackId'])
                    self.wait(lambda: self.stack(stack['StackId'])['StackStatus'] == 'DELETE_COMPLETE', 'failed proof application cleanup')
                    self.absent(resources)
                self.remove_bootstrap()
            except Exception as error:
                failures.append(repr(error))
            try:
                self.controller.stop()
            except Exception as error:
                failures.append(repr(error))
        self.report['cleanup_complete'] = not failures
        self.report['cleanup_errors'] = failures
        self.save()
        require(not failures, 'cleanup failed: ' + '; '.join(failures))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', required=True)
    parser.add_argument('--state-directory', required=True)
    parser.add_argument('--cdk', required=True)
    parser.add_argument('--node-path', required=True, help='node_modules containing official aws-cdk-lib and constructs')
    args = parser.parse_args()
    app = Proof(args)
    try:
        app.run()
    except BaseException as error:
        app.report['failure'] = repr(error)
        raise
    finally:
        app.cleanup()
    print(json.dumps({'complete': app.report.get('complete', False), 'cleanup_complete': app.report['cleanup_complete'],
                      'report': str(app.state / 'report.json')}, indent=2))


if __name__ == '__main__':
    main()
