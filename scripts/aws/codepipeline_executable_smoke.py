#!/usr/bin/env python3
"""Exercise real pipeline builds, deployment, current IAM, events and restart."""
import argparse
import gzip
import io
import json
import os
from pathlib import Path
import socket
import time
import urllib.request
import uuid
import zipfile

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

from stackd_process import StackdProcess

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--binary', required=True, type=Path)
parser.add_argument('--state-directory', required=True, type=Path)
parser.add_argument('--build-image', required=True, help='Local Linux image containing python3')
parser.add_argument('--docker-host', default='unix:///var/run/docker.sock')
parser.add_argument('--region', default='us-east-1')
parser.add_argument('--forwarding-identity', default='460678247002', help='Native-calibrated AppConfig CalledVia identifier for the region')
args = parser.parse_args()
state = args.state_directory.resolve()
state.mkdir(parents=True)

with socket.socket() as listener:
    listener.bind(('0.0.0.0', 0))
    port = listener.getsockname()[1]
endpoint = f'http://127.0.0.1:{port}'
environment = {k: v for k, v in os.environ.items() if not k.startswith('AWS_')}
environment.update(AWS_ACCESS_KEY_ID='test', AWS_SECRET_ACCESS_KEY='test', AWS_DEFAULT_REGION=args.region, AWS_EC2_METADATA_DISABLED='true')
process = StackdProcess(state)
command = [str(args.binary.resolve()), '-listen', f'0.0.0.0:{port}', '-public-endpoint', endpoint, '-database', str(state / 'state.sqlite'), '-clock-start', '2026-09-28T12:00:00Z', '-docker-host', args.docker_host, '-codebuild-runtime', '-compute-endpoint', f'http://host.docker.internal:{port}']
session = boto3.Session(aws_access_key_id='test', aws_secret_access_key='test', region_name=args.region)
clients = {name: session.client(name, endpoint_url=endpoint, config=Config(retries={'total_max_attempts': 1}, read_timeout=60, s3={'addressing_style': 'path'})) for name in ('sts', 'iam', 's3', 'codepipeline', 'codebuild', 'appconfig', 'events', 'sqs', 'sns', 'cloudtrail', 'logs')}
prefix = 'pipeline-smoke-' + uuid.uuid4().hex[:8]
report = {'state': str(state), 'region': args.region, 'controllers': process.runs, 'observations': {}, 'cleanup': [], 'complete': False}
cleanup = []

def save():
    (state / 'report.json').write_text(json.dumps(report, indent=2, default=str) + '\n')

def require(ok, message):
    if not ok:
        raise AssertionError(message)

def control(path, body=None):
    request = urllib.request.Request(endpoint + path, data=json.dumps(body or {}).encode(), headers={'Content-Type': 'application/json'})
    with urllib.request.urlopen(request, timeout=60) as response:
        return json.load(response)

def advance(seconds=1):
    control('/_stackd/clock', {'advance': str(seconds) + 's'})
    return control('/_stackd/jobs/drain?limit=4096')

def role(suffix, principal, actions):
    name = prefix + suffix
    trust = principal if isinstance(principal, dict) else {'Service': principal}
    result = clients['iam'].create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps({'Version': '2012-10-17', 'Statement': [{'Effect': 'Allow', 'Principal': trust, 'Action': 'sts:AssumeRole'}]}))['Role']
    def remove():
        for policy in clients['iam'].list_role_policies(RoleName=name)['PolicyNames']:
            clients['iam'].delete_role_policy(RoleName=name, PolicyName=policy)
        clients['iam'].delete_role(RoleName=name)
    cleanup.append(('role:' + name, remove))
    clients['iam'].put_role_policy(RoleName=name, PolicyName='owned', PolicyDocument=json.dumps({'Version': '2012-10-17', 'Statement': [{'Effect': 'Allow', 'Action': actions, 'Resource': '*'}]}))
    return result['Arn']

def bucket(name, versioned=False):
    request = {'Bucket': name}
    if args.region != 'us-east-1':
        request['CreateBucketConfiguration'] = {'LocationConstraint': args.region}
    clients['s3'].create_bucket(**request)
    def remove():
        versions = clients['s3'].list_object_versions(Bucket=name)
        objects = [{'Key': row['Key'], 'VersionId': row['VersionId']} for key in ('Versions', 'DeleteMarkers') for row in versions.get(key, [])]
        if objects:
            clients['s3'].delete_objects(Bucket=name, Delete={'Objects': objects})
        clients['s3'].delete_bucket(Bucket=name)
    cleanup.append(('bucket:' + name, remove))
    if versioned:
        clients['s3'].put_bucket_versioning(Bucket=name, VersioningConfiguration={'Status': 'Enabled'})
    return name

def wait_execution(execution_id, expected='Succeeded', expected_result=18):
    for _ in range(180):
        advance()
        for message in clients['sqs'].receive_message(QueueUrl=approval_queue, MaxNumberOfMessages=10).get('Messages', []):
            envelope = json.loads(message['Body'])
            notification = json.loads(envelope['Message'])
            approval = notification['approval']
            require(approval['pipelineName'] == prefix, 'Approval notification lost pipeline identity')
            if approval['actionName'] == 'Review':
                require(approval['customData'] == f'Built result {expected_result}' and approval['externalEntityLink'] == 'https://example.com/review',
                        'Detailed approval lost resolved build output or external link')
            else:
                require(approval['actionName'] == 'B' * 25 and approval['customData'] is None and approval['externalEntityLink'] is None,
                        'Minimal approval did not preserve explicit nullable fields')
                require(envelope['Subject'].endswith(' for action ' + 'B' * 24 + '...'),
                        'Long approval action subject did not match native truncation')
            clients['sqs'].delete_message(QueueUrl=approval_queue, ReceiptHandle=message['ReceiptHandle'])
            if not report['observations'].get('approval_restart'):
                process.stop()
                process.start(command, endpoint, environment=environment)
                advance()
                duplicate = clients['sqs'].receive_message(QueueUrl=approval_queue).get('Messages', [])
                require(not duplicate, 'Restart republished an already committed approval notification')
                current = clients['codepipeline'].get_pipeline_state(name=prefix)
                gate = next(stage for stage in current['stageStates'] if stage['stageName'] == 'Approve')
                require(gate['actionStates'][0]['latestExecution']['token'] == approval['token'],
                        'Restart replaced the notification approval token')
                report['observations']['approval_restart'] = True
            clients['codepipeline'].put_approval_result(pipelineName=prefix, stageName=approval['stageName'],
                actionName=approval['actionName'], token=approval['token'],
                result={'status': 'Approved', 'summary': 'Approved through the SNS/SQS notification'})
            report['observations'].setdefault('approval_notifications', []).append(envelope)
        execution = clients['codepipeline'].get_pipeline_execution(pipelineName=prefix, pipelineExecutionId=execution_id)['pipelineExecution']
        if execution['status'] not in ('InProgress', 'Stopping'):
            actions = clients['codepipeline'].list_action_executions(pipelineName=prefix, filter={'pipelineExecutionId': execution_id})['actionExecutionDetails']
            report['observations'][execution_id] = {'execution': execution, 'actions': actions}
            save()
            require(execution['status'] == expected, json.dumps({'execution': execution, 'actions': actions}, default=str))
            return execution, actions
        time.sleep(0.1)
    report['observations']['timeout'] = clients['codepipeline'].get_pipeline_state(name=prefix)
    save()
    raise TimeoutError('Pipeline did not settle; inspect report and controller logs')

try:
    process.start(command, endpoint, environment=environment)
    account = clients['sts'].get_caller_identity()['Account']
    pipeline_role = role('-pipeline', 'codepipeline.amazonaws.com', ['s3:*', 'kms:*', 'sns:Publish', 'codebuild:StartBuild', 'codebuild:BatchGetBuilds', 'appconfig:StartDeployment', 'appconfig:GetDeployment'])
    build_role = role('-build', 'codebuild.amazonaws.com', ['s3:*', 'kms:*', 'logs:*'])
    source_bucket = bucket(prefix + '-source', True)
    artifact_bucket = bucket(prefix + '-artifacts')
    audit_bucket = bucket(prefix + '-audit')
    trail_arn = f'arn:aws:cloudtrail:{args.region}:{account}:trail/{prefix}'
    clients['s3'].put_bucket_policy(Bucket=audit_bucket, Policy=json.dumps({'Version': '2012-10-17', 'Statement': [
        {'Effect': 'Allow', 'Principal': {'Service': 'cloudtrail.amazonaws.com'}, 'Action': 's3:GetBucketAcl', 'Resource': 'arn:aws:s3:::' + audit_bucket, 'Condition': {'StringEquals': {'aws:SourceArn': trail_arn}}},
        {'Effect': 'Allow', 'Principal': {'Service': 'cloudtrail.amazonaws.com'}, 'Action': 's3:PutObject', 'Resource': f'arn:aws:s3:::{audit_bucket}/AWSLogs/{account}/*', 'Condition': {'StringEquals': {'aws:SourceArn': trail_arn, 's3:x-amz-acl': 'bucket-owner-full-control'}}}
    ]}))
    clients['cloudtrail'].create_trail(Name=prefix, S3BucketName=audit_bucket, IncludeGlobalServiceEvents=False)
    def remove_trail():
        clients['cloudtrail'].stop_logging(Name=prefix)
        clients['cloudtrail'].delete_trail(Name=prefix)
    cleanup.append(('trail:' + prefix, remove_trail))
    clients['cloudtrail'].put_event_selectors(TrailName=prefix, AdvancedEventSelectors=[
        {'Name': 'Management', 'FieldSelectors': [{'Field': 'eventCategory', 'Equals': ['Management']}]},
        {'Name': 'OwnedObjects', 'FieldSelectors': [{'Field': 'eventCategory', 'Equals': ['Data']}, {'Field': 'resources.type', 'Equals': ['AWS::S3::Object']}, {'Field': 'resources.ARN', 'StartsWith': ['arn:aws:s3:::' + source_bucket + '/', 'arn:aws:s3:::' + artifact_bucket + '/']}]}
    ])
    clients['cloudtrail'].start_logging(Name=prefix)
    queue = clients['sqs'].create_queue(QueueName=prefix)['QueueUrl']
    cleanup.append(('queue:' + queue, lambda: clients['sqs'].delete_queue(QueueUrl=queue)))
    queue_arn = clients['sqs'].get_queue_attributes(QueueUrl=queue, AttributeNames=['QueueArn'])['Attributes']['QueueArn']
    capture_rule = clients['events'].put_rule(Name=prefix + '-capture', EventPattern=json.dumps({'source': ['aws.codepipeline'], 'detail': {'pipeline': [prefix], 'version': [1.0]}}))['RuleArn']
    cleanup.append(('rule:' + capture_rule, lambda: clients['events'].delete_rule(Name=prefix + '-capture')))
    clients['sqs'].set_queue_attributes(QueueUrl=queue, Attributes={'Policy': json.dumps({'Version': '2012-10-17', 'Statement': [{'Effect': 'Allow', 'Principal': {'Service': 'events.amazonaws.com'}, 'Action': 'sqs:SendMessage', 'Resource': queue_arn, 'Condition': {'ArnEquals': {'aws:SourceArn': capture_rule}}}]})})
    admitted = clients['events'].put_targets(Rule=prefix + '-capture', Targets=[{'Id': 'capture', 'Arn': queue_arn}])
    require(admitted['FailedEntryCount'] == 0, str(admitted))
    cleanup.append(('target:capture', lambda: clients['events'].remove_targets(Rule=prefix + '-capture', Ids=['capture'])))
    approval_topic = clients['sns'].create_topic(Name=prefix + '-approval')['TopicArn']
    cleanup.append(('topic:' + approval_topic, lambda: clients['sns'].delete_topic(TopicArn=approval_topic)))
    approval_queue = clients['sqs'].create_queue(QueueName=prefix + '-approval')['QueueUrl']
    cleanup.append(('queue:' + approval_queue, lambda: clients['sqs'].delete_queue(QueueUrl=approval_queue)))
    approval_queue_arn = clients['sqs'].get_queue_attributes(QueueUrl=approval_queue, AttributeNames=['QueueArn'])['Attributes']['QueueArn']
    clients['sqs'].set_queue_attributes(QueueUrl=approval_queue, Attributes={'Policy': json.dumps({'Version': '2012-10-17', 'Statement': [
        {'Effect': 'Allow', 'Principal': {'Service': 'sns.amazonaws.com'}, 'Action': 'sqs:SendMessage',
         'Resource': approval_queue_arn, 'Condition': {'ArnEquals': {'aws:SourceArn': approval_topic}}}]})})
    approval_subscription = clients['sns'].subscribe(TopicArn=approval_topic, Protocol='sqs', Endpoint=approval_queue_arn)['SubscriptionArn']
    cleanup.append(('subscription:' + approval_subscription, lambda: clients['sns'].unsubscribe(SubscriptionArn=approval_subscription)))
    zipped = io.BytesIO()
    with zipfile.ZipFile(zipped, 'w') as archive:
        archive.writestr('config.json', '{"value":17}')
        archive.writestr('transform.py', 'import json, os\np="config.json"\nv=json.load(open(p)); v["value"]+=int(os.environ["INCREMENT"])\nopen(p,"w").write(json.dumps(v))\nopen("result.txt","w").write(str(v["value"]))\nprint("actual transformed value", v["value"])\n')
        archive.writestr('buildspec.yml', 'version: 0.2\nenv:\n  exported-variables: [RESULT]\nphases:\n  build:\n    commands:\n      - python3 transform.py\n      - export RESULT=$(cat result.txt)\nartifacts:\n  files: [config.json]\n')
    source = clients['s3'].put_object(Bucket=source_bucket, Key='source.zip', Body=zipped.getvalue())
    project = prefix + '-project'
    clients['codebuild'].create_project(name=project, source={'type': 'CODEPIPELINE'}, artifacts={'type': 'CODEPIPELINE'}, environment={'type': 'LINUX_CONTAINER', 'image': args.build_image, 'computeType': 'BUILD_GENERAL1_SMALL'}, serviceRole=build_role)
    def remove_builds():
        ids = clients['codebuild'].list_builds_for_project(projectName=project).get('ids', [])
        if ids:
            result = clients['codebuild'].batch_delete_builds(ids=ids)
            require(not result.get('buildsNotDeleted'), str(result))
        clients['codebuild'].delete_project(name=project)
        advance()
    cleanup.append(('project-and-builds:' + project, remove_builds))
    app = clients['appconfig'].create_application(Name=prefix)['Id']
    cleanup.append(('application:' + app, lambda: clients['appconfig'].delete_application(ApplicationId=app)))
    env = clients['appconfig'].create_environment(ApplicationId=app, Name='production')['Id']
    cleanup.append(('environment:' + env, lambda: clients['appconfig'].delete_environment(ApplicationId=app, EnvironmentId=env)))
    profile = clients['appconfig'].create_configuration_profile(ApplicationId=app, Name='configuration', LocationUri='codepipeline://' + prefix, Type='AWS.Freeform')['Id']
    cleanup.append(('profile:' + profile, lambda: clients['appconfig'].delete_configuration_profile(ApplicationId=app, ConfigurationProfileId=profile)))
    strategy = clients['appconfig'].create_deployment_strategy(Name=prefix, DeploymentDurationInMinutes=0, FinalBakeTimeInMinutes=0, GrowthFactor=100, GrowthType='LINEAR', ReplicateTo='NONE')['Id']
    cleanup.append(('strategy:' + strategy, lambda: clients['appconfig'].delete_deployment_strategy(DeploymentStrategyId=strategy)))
    declaration = {'name': prefix, 'roleArn': pipeline_role, 'pipelineType': 'V2', 'executionMode': 'QUEUED', 'artifactStore': {'type': 'S3', 'location': artifact_bucket},
        'variables': [{'name': 'Increment', 'defaultValue': '1', 'description': 'Increment applied by the real build'}], 'stages': [
        {'name': 'Source', 'actions': [{'name': 'Source', 'actionTypeId': {'category': 'Source', 'owner': 'AWS', 'provider': 'S3', 'version': '1'}, 'configuration': {'S3Bucket': source_bucket, 'S3ObjectKey': 'source.zip', 'PollForSourceChanges': 'false'}, 'outputArtifacts': [{'name': 'SourceZip'}], 'runOrder': 1}]},
        {'name': 'Build', 'actions': [{'name': 'Build', 'namespace': 'Built', 'actionTypeId': {'category': 'Build', 'owner': 'AWS', 'provider': 'CodeBuild', 'version': '1'}, 'configuration': {'ProjectName': project, 'EnvironmentVariables': json.dumps([{'name': 'INCREMENT', 'value': '#{variables.Increment}', 'type': 'PLAINTEXT'}])}, 'inputArtifacts': [{'name': 'SourceZip'}], 'outputArtifacts': [{'name': 'Configuration'}], 'runOrder': 1}]},
        {'name': 'Approve', 'actions': [{'name': 'Review', 'actionTypeId': {'category': 'Approval', 'owner': 'AWS', 'provider': 'Manual', 'version': '1'},
            'configuration': {'NotificationArn': approval_topic, 'CustomData': 'Built result #{Built.RESULT}', 'ExternalEntityLink': 'https://example.com/review'}, 'runOrder': 1},
            {'name': 'B' * 25, 'actionTypeId': {'category': 'Approval', 'owner': 'AWS', 'provider': 'Manual', 'version': '1'},
             'configuration': {'NotificationArn': approval_topic}, 'runOrder': 2}]},
        {'name': 'Deploy', 'actions': [{'name': 'Deploy', 'actionTypeId': {'category': 'Deploy', 'owner': 'AWS', 'provider': 'AppConfig', 'version': '1'}, 'configuration': {'Application': app, 'Environment': env, 'ConfigurationProfile': profile, 'DeploymentStrategy': strategy, 'InputArtifactConfigurationPath': 'config.json'}, 'inputArtifacts': [{'name': 'Configuration'}], 'runOrder': 1}]}
    ]}
    clients['codepipeline'].create_pipeline(pipeline=declaration)
    cleanup.append(('pipeline:' + prefix, lambda: clients['codepipeline'].delete_pipeline(name=prefix)))
    execution_id = clients['codepipeline'].list_pipeline_executions(pipelineName=prefix)['pipelineExecutionSummaries'][0]['pipelineExecutionId']
    execution, actions = wait_execution(execution_id)
    data = clients['appconfig'].get_configuration(Application=app, Environment=env, Configuration=profile, ClientId='consumer')
    with data['Content'] as body:
        content = json.load(body)
    require(content == {'value': 18}, 'AppConfig did not consume transformed container output')
    build = next(action for action in actions if action['actionName'] == 'Build')
    deploy = next(action for action in actions if action['actionName'] == 'Deploy')
    build_id = build['output']['executionResult']['externalExecutionId']
    built = clients['codebuild'].batch_get_builds(ids=[build_id])['builds'][0]
    require(built['resolvedSourceVersion'] == source['VersionId'], 'Copied artifact replaced original revision')
    require(build['output']['outputVariables']['RESULT'] == '18', 'Real exported build variable missing')
    require(data['ConfigurationVersion'] == deploy['actionExecutionId'], 'AppConfig version is not the owning deployment action')
    location = build['output']['outputArtifacts'][0]['s3location']
    stored = clients['s3'].get_object(Bucket=location['bucket'], Key=location['key'])
    with stored['Body'] as body:
        artifact = body.read()
    require(stored['ServerSideEncryption'] == 'aws:kms', 'Pipeline artifact is not encrypted')
    require('VersionId' not in stored, 'Unversioned artifact store acquired an invented version')
    with zipfile.ZipFile(io.BytesIO(artifact)) as archive:
        require(json.loads(archive.read('config.json')) == {'value': 18}, 'Published ZIP bytes differ from deployed content')
    consumer_role = role('-consumer', {'AWS': f'arn:aws:iam::{account}:root'}, ['appconfig:StartDeployment', 'kms:Decrypt'])
    consumer_credentials = clients['sts'].assume_role(RoleArn=consumer_role, RoleSessionName='ArtifactReader')['Credentials']
    consumer_clients = {name: session.client(name, endpoint_url=endpoint,
        aws_access_key_id=consumer_credentials['AccessKeyId'], aws_secret_access_key=consumer_credentials['SecretAccessKey'],
        aws_session_token=consumer_credentials['SessionToken'], config=Config(retries={'total_max_attempts': 1},
        s3={'addressing_style': 'path'})) for name in ('appconfig', 's3')}
    deployment_request = {'ApplicationId': app, 'EnvironmentId': env, 'ConfigurationProfileId': profile,
                          'ConfigurationVersion': deploy['actionExecutionId'], 'DeploymentStrategyId': strategy}
    forwarding = []
    forwarding_cases = [(args.forwarding_identity, 'Success'), ('appconfig.amazonaws.com', 'BadRequestException')]
    if args.forwarding_identity != '460678247002':
        forwarding_cases.append(('460678247002', 'BadRequestException'))
    for via, expected in forwarding_cases:
        condition = {'StringEquals': {'aws:CalledViaFirst': via, 'aws:CalledViaLast': via},
                     'ForAllValues:StringEquals': {'aws:CalledVia': [via]},
                     'Null': {'aws:CalledVia': 'false'}, 'Bool': {'aws:ViaAWSService': 'true'}}
        clients['iam'].put_role_policy(RoleName=prefix + '-consumer', PolicyName='artifact',
            PolicyDocument=json.dumps({'Version': '2012-10-17', 'Statement': [{'Effect': 'Allow',
                'Action': ['s3:GetObject', 's3:GetObjectVersion'], 'Resource': f'arn:aws:s3:::{artifact_bucket}/*',
                'Condition': condition}]}))
        try:
            with consumer_clients['s3'].get_object(Bucket=location['bucket'], Key=location['key'])['Body']:
                raise AssertionError('Forwarded-only permission authorized a direct artifact read')
        except ClientError as error:
            require(error.response['Error']['Code'] == 'AccessDenied', str(error))
        try:
            forwarded = consumer_clients['appconfig'].start_deployment(**deployment_request)
            code = 'Success'
        except ClientError as error:
            forwarded = error.response
            code = error.response['Error']['Code']
        forwarding.append({'condition': condition, 'code': code, 'response': forwarded})
        report['observations']['forwarded_artifact_authority'] = forwarding
        save()
        require(code == expected, f'Forwarded artifact authority for {via}: expected {expected}, received {code}')
        advance()
    for consumer_client in consumer_clients.values():
        consumer_client.close()
    events_role = role('-events', 'events.amazonaws.com', ['codepipeline:StartPipelineExecution'])
    start_rule = clients['events'].put_rule(Name=prefix + '-start', EventPattern=json.dumps({'source': ['stackd.pipeline-smoke']}))['RuleArn']
    cleanup.append(('rule:' + start_rule, lambda: clients['events'].delete_rule(Name=prefix + '-start')))
    admitted = clients['events'].put_targets(Rule=prefix + '-start', Targets=[{'Id': 'pipeline', 'Arn': f'arn:aws:codepipeline:{args.region}:{account}:{prefix}', 'RoleArn': events_role, 'InputTransformer': {'InputPathsMap': {'revision': '$.detail.version'}, 'InputTemplate': '{"sourceRevisions":[{"actionName":"Source","revisionType":"S3_OBJECT_VERSION_ID","revisionValue":<revision>}]}'}}])
    require(admitted['FailedEntryCount'] == 0, str(admitted))
    cleanup.append(('target:pipeline', lambda: clients['events'].remove_targets(Rule=prefix + '-start', Ids=['pipeline'])))
    newer = io.BytesIO()
    with zipfile.ZipFile(io.BytesIO(zipped.getvalue())) as original, zipfile.ZipFile(newer, 'w') as changed:
        for member in original.namelist():
            changed.writestr(member, '{"value":29}' if member == 'config.json' else original.read(member))
    latest_source = clients['s3'].put_object(Bucket=source_bucket, Key='source.zip', Body=newer.getvalue())
    incoming = clients['events'].put_events(Entries=[{'Source': 'stackd.pipeline-smoke', 'DetailType': 'Deploy', 'Detail': json.dumps({'version': source['VersionId']})}])
    require(incoming['FailedEntryCount'] == 0, str(incoming))
    event_id = incoming['Entries'][0]['EventId']
    for _ in range(20):
        advance()
        triggered = [row for row in clients['codepipeline'].list_pipeline_executions(pipelineName=prefix)['pipelineExecutionSummaries'] if row['pipelineExecutionId'] != execution_id]
        if triggered:
            break
    require(bool(triggered), 'EventBridge did not start the target pipeline')
    event_execution_id = triggered[0]['pipelineExecutionId']
    event_execution, event_actions = wait_execution(event_execution_id)
    require(event_execution['trigger'] == {'triggerType': 'CloudWatchEvent', 'triggerDetail': start_rule}, 'EventBridge trigger context was lost')
    require(event_execution['artifactRevisions'][0]['revisionId'] == source['VersionId'] != latest_source['VersionId'], 'Transformer did not select the older source')
    event_build = next(action for action in event_actions if action['actionName'] == 'Build')
    location = event_build['output']['outputArtifacts'][0]['s3location']
    with clients['s3'].get_object(Bucket=location['bucket'], Key=location['key'])['Body'] as body:
        with zipfile.ZipFile(io.BytesIO(body.read())) as archive:
            require(json.loads(archive.read('config.json')) == {'value': 18}, 'Event-selected old bytes were not executed by the real build')
    clients['iam'].put_role_policy(RoleName=prefix + '-pipeline', PolicyName='deny-deploy', PolicyDocument=json.dumps({'Version': '2012-10-17', 'Statement': [{'Effect': 'Deny', 'Action': 'appconfig:StartDeployment', 'Resource': '*'}]}))
    denied_id = clients['codepipeline'].start_pipeline_execution(name=prefix, sourceRevisions=[{'actionName': 'Source', 'revisionType': 'S3_OBJECT_VERSION_ID', 'revisionValue': source['VersionId']}])['pipelineExecutionId']
    _, denied_actions = wait_execution(denied_id, 'Failed')
    refused = next(action for action in denied_actions if action['actionName'] == 'Deploy')
    require(refused['output']['executionResult']['errorDetails']['code'] == 'PermissionError', 'AppConfig permission refusal lost native action classification')
    clients['iam'].delete_role_policy(RoleName=prefix + '-pipeline', PolicyName='deny-deploy')
    clients['codepipeline'].retry_stage_execution(pipelineName=prefix, stageName='Deploy', pipelineExecutionId=denied_id, retryMode='FAILED_ACTIONS')
    _, recovered_actions = wait_execution(denied_id)
    recovered_deploy = [a for a in recovered_actions if a['actionName'] == 'Deploy' and a['status'] == 'Succeeded'][0]
    require(recovered_deploy['actionExecutionId'] != refused['actionExecutionId'], 'Retry reused the failed action identity')
    recovered_build = next(action for action in recovered_actions if action['actionName'] == 'Build')
    location = recovered_build['output']['outputArtifacts'][0]['s3location']
    clients['iam'].put_role_policy(RoleName=prefix + '-pipeline', PolicyName='deny-decrypt', PolicyDocument=json.dumps({'Version': '2012-10-17', 'Statement': [{'Effect': 'Deny', 'Action': 'kms:Decrypt', 'Resource': '*'}]}))
    kms_denied_id = clients['codepipeline'].start_pipeline_execution(name=prefix, sourceRevisions=[{'actionName': 'Source', 'revisionType': 'S3_OBJECT_VERSION_ID', 'revisionValue': source['VersionId']}])['pipelineExecutionId']
    _, kms_denied_actions = wait_execution(kms_denied_id, 'Failed')
    require(next(a for a in kms_denied_actions if a['status'] == 'Failed')['actionName'] == 'Deploy', 'Current caller KMS denial did not reject artifact consumption')
    clients['iam'].delete_role_policy(RoleName=prefix + '-pipeline', PolicyName='deny-decrypt')
    clients['codepipeline'].retry_stage_execution(pipelineName=prefix, stageName='Deploy', pipelineExecutionId=kms_denied_id, retryMode='FAILED_ACTIONS')
    _, kms_recovered_actions = wait_execution(kms_denied_id)
    location = next(a for a in kms_recovered_actions if a['actionName'] == 'Build')['output']['outputArtifacts'][0]['s3location']
    retained_actions = {action['actionExecutionId'] for action in recovered_actions}
    latest_actions = {action['actionExecutionId'] for action in recovered_actions
                      if action['actionName'] != 'Deploy' or action['actionExecutionId'] == recovered_deploy['actionExecutionId']}
    history_filters = {}
    for time_range, expected in [('All', retained_actions), ('Latest', latest_actions)]:
        pages = list(clients['codepipeline'].get_paginator('list_action_executions').paginate(
            pipelineName=prefix, filter={'latestInPipelineExecution': {
                'pipelineExecutionId': denied_id, 'startTimeRange': time_range}},
            PaginationConfig={'PageSize': 1}))
        selected = [action['actionExecutionId'] for page in pages for action in page['actionExecutionDetails']]
        history_filters[time_range] = pages
        require(set(selected) == expected and len(selected) == len(expected),
                f'{time_range} action history lost retained actions or selected superseded attempts')
    report['observations']['action_history_filters'] = history_filters
    advance(300)
    delivered = []
    while True:
        messages = clients['sqs'].receive_message(QueueUrl=queue, MaxNumberOfMessages=10).get('Messages', [])
        if not messages:
            break
        for message in messages:
            delivered.append(json.loads(message['Body']))
            clients['sqs'].delete_message(QueueUrl=queue, ReceiptHandle=message['ReceiptHandle'])
    require({e['detail-type'] for e in delivered} == {'CodePipeline Pipeline Execution State Change', 'CodePipeline Stage Execution State Change', 'CodePipeline Action Execution State Change'}, 'Configured SQS target missed lifecycle event classes')
    require(any(e['detail']['state'] == 'RESUMED' and e['detail']['pipeline-execution-attempt'] == 2 for e in delivered), 'Retry lifecycle did not reach the queue')
    require(any(e['detail-type'] == 'CodePipeline Stage Execution State Change' and e['detail']['pipeline-execution-attempt'] == 0 for e in delivered), 'Initial native stage counter was lost')
    audit = []
    for obj in clients['s3'].list_objects_v2(Bucket=audit_bucket).get('Contents', []):
        if obj['Key'].endswith('.json.gz'):
            with clients['s3'].get_object(Bucket=audit_bucket, Key=obj['Key'])['Body'] as body:
                audit.extend(json.loads(gzip.decompress(body.read()))['Records'])
    started = [row for row in audit if row['eventSource'] == 'codepipeline.amazonaws.com' and row['eventName'] == 'StartPipelineExecution' and (row.get('responseElements') or {}).get('pipelineExecutionId') == event_execution_id]
    require(len(started) == 1, 'EventBridge-started execution was not recorded in delivered CloudTrail gzip')
    require(started[0]['userIdentity']['invokedBy'] == 'events.amazonaws.com', 'CloudTrail lost the actual invoking service')
    require(started[0]['requestParameters']['clientRequestToken'] != event_id, 'Target reused the incoming event ID as native client token')
    require(any(row['eventSource'] == 'codebuild.amazonaws.com' and row['eventName'] == 'StartBuild' for row in audit), 'Build management calls did not reach the trail')
    require(any(row['eventSource'] == 'appconfig.amazonaws.com' and row['eventName'] == 'StartDeployment' for row in audit), 'Deployment management calls did not reach the trail')
    require(any(row['eventCategory'] == 'Data' and row['eventSource'] == 's3.amazonaws.com' for row in audit), 'Selected S3 data events did not reach the trail')
    forwarded_reads = [row for row in audit if row['eventSource'] == 's3.amazonaws.com'
                       and row['eventName'] == 'GetObject'
                       and row['userIdentity'].get('invokedBy') == 'AWS Internal'
                       and row['userIdentity'].get('sessionContext', {}).get('sessionIssuer', {}).get('arn') == consumer_role]
    require(len(forwarded_reads) == len(forwarding_cases), 'Trail lost the caller identity on forwarded artifact reads')
    require(any('errorCode' not in row for row in forwarded_reads)
            and any(row.get('errorCode') == 'AccessDenied' for row in forwarded_reads),
            'Trail must retain both admitted and denied forwarded artifact reads')
    require(all(row['sourceIPAddress'] == 'AWS Internal' and row['userAgent'] == 'AWS Internal'
                and 'versionId' not in row['requestParameters'] for row in forwarded_reads),
            'Forwarded artifact audit context differs from native S3 reads')
    request_ids = [row['requestID'] for row in forwarded_reads]
    require(len(set(request_ids)) == len(request_ids)
            and not set(request_ids).intersection(item['response']['ResponseMetadata']['RequestId'] for item in forwarding),
            'Downstream S3 reads reused the parent AppConfig request identity')
    report['observations']['lifecycle_events'] = delivered
    report['observations']['cloudtrail'] = audit
    process.stop()
    process.start(command, endpoint, environment=environment)
    recovered = clients['appconfig'].get_configuration(Application=app, Environment=env, Configuration=profile, ClientId='after-restart')
    with recovered['Content'] as body:
        require(json.load(body) == {'value': 18}, 'Restart lost accepted deployed bytes')
    restarted_history = {}
    for time_range, before in history_filters.items():
        pages = list(clients['codepipeline'].get_paginator('list_action_executions').paginate(
            pipelineName=prefix, filter={'latestInPipelineExecution': {
                'pipelineExecutionId': denied_id, 'startTimeRange': time_range}},
            PaginationConfig={'PageSize': 1}))
        ids = lambda rows: [action['actionExecutionId'] for page in rows for action in page['actionExecutionDetails']]
        require(ids(pages) == ids(before), f'Restart changed {time_range} action history')
        restarted_history[time_range] = pages
    report['observations']['restarted_action_history_filters'] = restarted_history
    clients['s3'].delete_object(Bucket=location['bucket'], Key=location['key'])
    recovered = clients['appconfig'].get_configuration(Application=app, Environment=env, Configuration=profile, ClientId='after-artifact-deletion')
    with recovered['Content'] as body:
        require(json.load(body) == {'value': 18}, 'Removing source artifact destroyed accepted deployment')
    build_stages = declaration['stages']
    fifo_topic = clients['sns'].create_topic(Name=prefix + '.fifo', Attributes={'FifoTopic': 'true'})['TopicArn']
    cleanup.append(('approval-fifo-topic:' + fifo_topic, lambda: clients['sns'].delete_topic(TopicArn=fifo_topic)))
    notification_failures = report['observations']['approval_configuration_failures'] = []
    for target in (fifo_topic, f'arn:aws:sns:{args.region}:{account}:{prefix}-absent'):
        declaration['stages'] = [declaration['stages'][0], {'name': 'ApprovalErrors', 'actions': [
            {'name': 'Review', 'actionTypeId': {'category': 'Approval', 'owner': 'AWS', 'provider': 'Manual', 'version': '1'},
             'configuration': {'NotificationArn': target}, 'runOrder': 1}]}]
        clients['codepipeline'].update_pipeline(pipeline=declaration)
        failed_id = clients['codepipeline'].start_pipeline_execution(name=prefix)['pipelineExecutionId']
        wait_execution(failed_id, 'Failed')
        failed_state = clients['codepipeline'].get_pipeline_state(name=prefix)
        history = clients['codepipeline'].list_action_executions(pipelineName=prefix, filter={'pipelineExecutionId': failed_id})
        action = failed_state['stageStates'][1]['actionStates'][0]['latestExecution']
        retained = next(row['output']['executionResult'] for row in history['actionExecutionDetails'] if row['actionName'] == 'Review')
        notification_failures.append({'target': target, 'state': failed_state, 'history': history})
        require(action['errorDetails']['code'] == 'ConfigurationError' and 'token' not in action,
                f'Notification configuration failure lost native classification: {action}')
        require(retained['externalExecutionId'] == action['actionExecutionId']
                and retained['errorDetails'] == {'code': 'ConfigurationError'}
                and retained['externalExecutionSummary'] == action['errorDetails']['message'],
                f'Notification failure history lost native projection: {retained}')
    foreign_account = '444455556666'
    require(account != foreign_account, 'Cross-account smoke requires distinct accounts')
    foreign_session = boto3.Session(aws_access_key_id=foreign_account, aws_secret_access_key='test', region_name=args.region)
    foreign = {name: foreign_session.client(name, endpoint_url=endpoint, config=Config(retries={'total_max_attempts': 1}))
               for name in ('sns', 'sqs')}
    foreign_topic = foreign['sns'].create_topic(Name=prefix + '-foreign')['TopicArn']
    cleanup.append(('foreign-topic:' + foreign_topic, lambda: foreign['sns'].delete_topic(TopicArn=foreign_topic)))
    foreign_original_policy = foreign['sns'].get_topic_attributes(TopicArn=foreign_topic)['Attributes']['Policy']
    foreign_queue = foreign['sqs'].create_queue(QueueName=prefix + '-foreign')['QueueUrl']
    cleanup.append(('foreign-queue:' + foreign_queue, lambda: foreign['sqs'].delete_queue(QueueUrl=foreign_queue)))
    foreign_queue_arn = foreign['sqs'].get_queue_attributes(QueueUrl=foreign_queue, AttributeNames=['QueueArn'])['Attributes']['QueueArn']
    foreign['sqs'].set_queue_attributes(QueueUrl=foreign_queue, Attributes={'Policy': json.dumps({'Version': '2012-10-17', 'Statement': [
        {'Effect': 'Allow', 'Principal': {'Service': 'sns.amazonaws.com'}, 'Action': 'sqs:SendMessage', 'Resource': foreign_queue_arn,
         'Condition': {'ArnEquals': {'aws:SourceArn': foreign_topic}}}]})})
    foreign_subscription = foreign['sns'].subscribe(TopicArn=foreign_topic, Protocol='sqs', Endpoint=foreign_queue_arn)['SubscriptionArn']
    cleanup.append(('foreign-subscription:' + foreign_subscription, lambda: foreign['sns'].unsubscribe(SubscriptionArn=foreign_subscription)))
    foreign['sns'].set_topic_attributes(TopicArn=foreign_topic, AttributeName='Policy', AttributeValue=json.dumps({
        'Version': '2012-10-17', 'Statement': [{'Effect': 'Allow', 'Principal': {'AWS': pipeline_role},
                                             'Action': 'sns:Publish', 'Resource': foreign_topic}]}))
    declaration['stages'][1]['actions'][0]['configuration']['NotificationArn'] = foreign_topic
    clients['codepipeline'].update_pipeline(pipeline=declaration)
    foreign_id = clients['codepipeline'].start_pipeline_execution(name=prefix)['pipelineExecutionId']
    for _ in range(180):
        advance()
        messages = foreign['sqs'].receive_message(QueueUrl=foreign_queue, MaxNumberOfMessages=10).get('Messages', [])
        if messages:
            require(len(messages) == 1, 'Cross-account approval published duplicate notifications')
            foreign_envelope = json.loads(messages[0]['Body'])
            foreign_approval = json.loads(foreign_envelope['Message'])['approval']
            require(foreign_approval['pipelineName'] == prefix and foreign_approval['stageName'] == 'ApprovalErrors',
                    'Cross-account notification lost admitted pipeline identity')
            clients['codepipeline'].put_approval_result(pipelineName=prefix, stageName=foreign_approval['stageName'],
                actionName=foreign_approval['actionName'], token=foreign_approval['token'],
                result={'status': 'Approved', 'summary': 'Approved from the other account notification'})
            foreign['sqs'].delete_message(QueueUrl=foreign_queue, ReceiptHandle=messages[0]['ReceiptHandle'])
            break
    else:
        raise TimeoutError('Cross-account approval notification was not delivered')
    cross_account = report['observations']['approval_cross_account'] = {
        'topic': foreign_topic, 'notification': foreign_envelope, 'execution': wait_execution(foreign_id), 'failures': []}
    foreign['sns'].set_topic_attributes(TopicArn=foreign_topic, AttributeName='Policy', AttributeValue=foreign_original_policy)
    for foreign_target in (foreign_topic, f'arn:aws:sns:{args.region}:{foreign_account}:{prefix}-absent'):
        declaration['stages'][1]['actions'][0]['configuration']['NotificationArn'] = foreign_target
        clients['codepipeline'].update_pipeline(pipeline=declaration)
        foreign_denied_id = clients['codepipeline'].start_pipeline_execution(name=prefix)['pipelineExecutionId']
        wait_execution(foreign_denied_id, 'Failed')
        foreign_state = clients['codepipeline'].get_pipeline_state(name=prefix)
        action = foreign_state['stageStates'][1]['actionStates'][0]['latestExecution']
        require(action['errorDetails']['code'] == 'PermissionError' and 'token' not in action,
                f'Cross-account publication failure lost native classification: {action}')
        require(not foreign['sqs'].receive_message(QueueUrl=foreign_queue).get('Messages'),
                'Denied cross-account publication reached the queue')
        cross_account['failures'].append({'target': foreign_target, 'state': foreign_state})
    declaration['stages'] = build_stages
    clients['codepipeline'].update_pipeline(pipeline=declaration)
    variable_execution_id = clients['codepipeline'].start_pipeline_execution(name=prefix,
        variables=[{'name': 'Increment', 'value': '2'}],
        sourceRevisions=[{'actionName': 'Source', 'revisionType': 'S3_OBJECT_VERSION_ID', 'revisionValue': source['VersionId']}])['pipelineExecutionId']
    variable_execution, variable_actions = wait_execution(variable_execution_id, expected_result=19)
    require(variable_execution['variables'] == [{'name': 'Increment', 'resolvedValue': '2'}],
            'Execution did not retain its explicit pipeline variable binding')
    variable_deployment = clients['appconfig'].get_configuration(Application=app, Environment=env, Configuration=profile, ClientId='variable-override')
    with variable_deployment['Content'] as body:
        variable_content = json.load(body)
    require(variable_content == {'value': 19}, 'Pipeline override did not reach the real build and deployed bytes')
    declaration['variables'][0]['defaultValue'] = '3'
    clients['codepipeline'].update_pipeline(pipeline=declaration)
    process.stop()
    process.start(command, endpoint, environment=environment)
    retained_variables = clients['codepipeline'].get_pipeline_execution(pipelineName=prefix, pipelineExecutionId=variable_execution_id)['pipelineExecution']['variables']
    require(retained_variables == variable_execution['variables'], 'Definition update/restart changed admitted variables')
    recovered = clients['appconfig'].get_configuration(Application=app, Environment=env, Configuration=profile, ClientId='variable-restart')
    with recovered['Content'] as body:
        require(json.load(body) == variable_content, 'Restart lost variable-driven deployment bytes')
    report['observations']['pipeline_variables'] = {'execution': variable_execution, 'actions': variable_actions,
        'content': variable_content, 'retained_variables': retained_variables, 'updated_default': '3'}
    report['observations']['content'] = content
    report['observations']['build'] = built
    report['observations']['artifact_encryption'] = stored.get('SSEKMSKeyId')
    report['complete'] = True
except BaseException as error:
    report['failure'] = {'type': type(error).__name__, 'message': str(error)}
    raise
finally:
    for name, remove in reversed(cleanup):
        try:
            remove()
            report['cleanup'].append({'resource': name, 'deleted': True})
        except Exception as error:
            report['cleanup'].append({'resource': name, 'error': str(error)})
            report['complete'] = False
    try:
        process.stop()
    finally:
        save()
        print(json.dumps({'report': str(state / 'report.json'), 'complete': report['complete'], 'controllers': process.runs}), flush=True)
        if not report['complete'] and 'failure' not in report:
            raise RuntimeError('Owned resource cleanup failed; inspect report.json')
