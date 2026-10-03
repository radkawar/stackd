#!/usr/bin/env python3
"""Bounded exact-owned native manual rollback calibration; no compute."""
import argparse
import copy
import io
import json
import os
from pathlib import Path
import time
import uuid
import zipfile

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError
from signed_requests import signed_post


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--account', required=True, help='Native AWS account ID that must match the STS caller')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        raise RuntimeError('Refusing to overwrite evidence')
    env = dict(os.environ, AWS_PROFILE='default', AWS_REGION='us-east-1', AWS_IGNORE_CONFIGURED_ENDPOINT_URLS='true')
    session = boto3.Session(profile_name='default', region_name='us-east-1')
    config = Config(retries={'total_max_attempts': 1}, connect_timeout=10, read_timeout=30, ignore_configured_endpoint_urls=True)
    clients = {s: session.client(s, config=config) for s in ('sts', 'iam', 's3')}
    actor = clients['sts'].get_caller_identity()
    if actor['Account'] != args.account:
        raise RuntimeError('Wrong native account')
    name = 'stackd-rollback-' + uuid.uuid4().hex[:12]
    source, dest = name + '-src', name + '-dst'
    owned = {'role': False, 'policy': False, 'pipeline': False, 'buckets': []}
    started = time.monotonic()
    evidence = {'actor': actor, 'region': 'us-east-1', 'name': name, 'owned': owned,
                'calls': [], 'cleanup': [], 'complete': False, 'cleanup_verified': False,
                'sources': ['https://docs.aws.amazon.com/codepipeline/latest/userguide/stage-rollback.html',
                            'https://docs.aws.amazon.com/codepipeline/latest/APIReference/API_RollbackStage.html']}

    def save():
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(evidence, indent=2, default=str) + '\n')

    def retain(label, operation, params, output, code, cleanup=False):
        evidence['cleanup' if cleanup else 'calls'].append(dict(label=label, operation=operation, parameters=params,
            output=output, code=code, elapsed=round(time.monotonic()-started, 3)))
        save()
        print(label + ': ' + code, flush=True)
        return output

    def sdk(service, method, params, cleanup=False):
        captured = {k: v.hex() if isinstance(v, bytes) else v for k, v in params.items()}
        try:
            out = getattr(clients[service], method)(**params)
            if method == 'get_object':
                stream = out.pop('Body')
                try:
                    out['bytes_hex'] = stream.read().hex()
                finally:
                    stream.close()
            return retain(method, method, captured, out, 'Success', cleanup)
        except ClientError as err:
            retain(method, method, captured, err.response, err.response['Error']['Code'], cleanup)
            raise

    def cp(label, op, params, strict=True, cleanup=False):
        if not cleanup and time.monotonic()-started > 1500:
            raise RuntimeError('Overall deadline')
        time.sleep(1.1)
        response = signed_post('codepipeline.us-east-1.amazonaws.com', 'codepipeline', json.dumps(params).encode(),
            {'content-type': 'application/x-amz-json-1.1', 'x-amz-target': 'CodePipeline_20150709.' + op}, env)
        out = json.loads(response.body or b'{}')
        code = 'Success' if response.status == 200 else out['__type'].split('#')[-1]
        retain(label, op, params, out, code, cleanup)
        if strict and code != 'Success':
            raise RuntimeError(label + ': ' + json.dumps(out))
        return out

    def snapshot(label, execution):
        cp(label+'/execution', 'GetPipelineExecution', dict(pipelineName=name, pipelineExecutionId=execution))
        cp(label+'/actions', 'ListActionExecutions', dict(pipelineName=name, filter=dict(pipelineExecutionId=execution)))
        cp(label+'/state', 'GetPipelineState', dict(name=name))
        cp(label+'/history', 'ListPipelineExecutions', dict(pipelineName=name))

    def wait(execution=None, approval=False):
        deadline = time.monotonic()+180
        while time.monotonic() < deadline:
            if execution is None:
                rows = cp('find', 'ListPipelineExecutions', dict(pipelineName=name)).get('pipelineExecutionSummaries', [])
                if rows:
                    execution = rows[0]['pipelineExecutionId']
            if execution:
                out = cp('wait', 'GetPipelineExecution', dict(pipelineName=name, pipelineExecutionId=execution))['pipelineExecution']
                if out['status'] not in ('InProgress', 'Stopping'):
                    return execution
                if approval:
                    state = cp('wait-approval', 'GetPipelineState', dict(name=name))
                    for stage in state['stageStates']:
                        for action in stage['actionStates']:
                            token = action.get('latestExecution', {}).get('token')
                            if token and stage.get('latestExecution', {}).get('pipelineExecutionId') == execution:
                                return execution, token
            time.sleep(3)
        raise RuntimeError('Execution deadline')

    def start():
        return cp('start', 'StartPipelineExecution', dict(name=name))['pipelineExecutionId']

    def rollback(label, target, stage='Deploy', strict=False):
        return cp(label, 'RollbackStage', dict(pipelineName=name, stageName=stage, targetPipelineExecutionId=target), strict)

    def upload(value):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, 'w') as z:
            z.writestr('value.txt', value)
        sdk('s3', 'put_object', dict(Bucket=source, Key='source.zip', Body=buf.getvalue()))

    try:
        role = sdk('iam', 'create_role', dict(RoleName=name, AssumeRolePolicyDocument=json.dumps({'Version':'2012-10-17','Statement':[{'Effect':'Allow','Principal':{'Service':'codepipeline.amazonaws.com'},'Action':'sts:AssumeRole'}]}), Tags=[dict(Key='stackd-probe', Value=name)]))['Role']
        owned['role'] = True
        sdk('iam', 'put_role_policy', dict(RoleName=name, PolicyName='owned', PolicyDocument=json.dumps({'Version':'2012-10-17','Statement':[{'Effect':'Allow','Action':'s3:*','Resource':['arn:aws:s3:::'+b+s for b in (source,dest) for s in ('','/*')]}]})))
        owned['policy'] = True
        for bucket in (source, dest):
            sdk('s3','create_bucket',dict(Bucket=bucket))
            owned['buckets'].append(bucket)
            sdk('s3','put_bucket_versioning',dict(Bucket=bucket, VersioningConfiguration=dict(Status='Enabled')))
        upload('v1\n')
        declaration = dict(name=name, roleArn=role['Arn'], artifactStore=dict(type='S3', location=source), pipelineType='V2', executionMode='SUPERSEDED', variables=[dict(name='Release',defaultValue='v1')], stages=[
            dict(name='Source',actions=[dict(name='Source',actionTypeId=dict(category='Source',owner='AWS',provider='S3',version='1'),configuration=dict(S3Bucket=source,S3ObjectKey='source.zip',PollForSourceChanges='false'),outputArtifacts=[dict(name='SourceZip')],namespace='Src')]),
            dict(name='Deploy',actions=[dict(name='Deploy',actionTypeId=dict(category='Deploy',owner='AWS',provider='S3',version='1'),configuration=dict(BucketName=dest,Extract='true',ObjectKey='#{variables.Release}'),inputArtifacts=[dict(name='SourceZip')])]),
            dict(name='Downstream',actions=[dict(name='Final',actionTypeId=dict(category='Deploy',owner='AWS',provider='S3',version='1'),configuration=dict(BucketName=dest,Extract='true',ObjectKey='final'),inputArtifacts=[dict(name='SourceZip')])])])
        time.sleep(15)
        cp('create','CreatePipeline',dict(pipeline=declaration))
        owned['pipeline'] = True
        v1 = wait()
        snapshot('v1',v1)
        rollback('unknown-stage',v1,'Missing')
        rollback('unknown-execution',str(uuid.uuid4()))
        rollback('malformed-execution','bad')
        upload('v2\n')
        v2 = cp('v2-start','StartPipelineExecution',dict(name=name,variables=[dict(name='Release',value='v2')]))['pipelineExecutionId']
        wait(v2)
        snapshot('v2',v2)
        rb = rollback('rollback-v1',v1,strict=True)['pipelineExecutionId']
        wait(rb)
        snapshot('rollback-v1',rb)
        sdk('s3','get_object',dict(Bucket=dest,Key='v1/value.txt'))
        sdk('s3','get_object',dict(Bucket=dest,Key='final/value.txt'))
        source_rollback = rollback('source-stage',v1,'Source',strict=True)['pipelineExecutionId']
        wait(source_rollback)
        snapshot('source-rollback',source_rollback)
        rollback('rollback-target-rollback',rb)
        cp('retry-success-rollback','RetryStageExecution',dict(pipelineName=name,stageName='Deploy',pipelineExecutionId=rb,retryMode='ALL_ACTIONS'),False)
        cp('stop-success-rollback','StopPipelineExecution',dict(pipelineName=name,pipelineExecutionId=rb,abandon=True),False)
        again = rollback('same-target-again',v1,strict=True)['pipelineExecutionId']
        wait(again)
        # A held approval makes active-stage, stop and retry boundaries observable.
        declaration['stages'][1]['actions'].append(dict(name='Approve',runOrder=2,actionTypeId=dict(category='Approval',owner='AWS',provider='Manual',version='1'),configuration={}))
        cp('add-approval','UpdatePipeline',dict(pipeline=declaration))
        rollback('outdated-target',v1)
        approved, token = wait(start(),approval=True)
        rollback('running-target',approved)
        cp('approve','PutApprovalResult',dict(pipelineName=name,stageName='Deploy',actionName='Approve',token=token,result=dict(status='Approved',summary='owned')))
        wait(approved)
        running, token = wait(start(),approval=True)
        rollback('running-current-stage',approved)
        cp('abandon-current','StopPipelineExecution',dict(pipelineName=name,pipelineExecutionId=running,abandon=True))
        wait(running)
        stopped_rb = rollback('rollback-stopped-current',approved,strict=True)['pipelineExecutionId']
        wait(stopped_rb,approval=True)
        snapshot('rollback-held',stopped_rb)
        rollback('concurrent-rollback',approved)
        cp('stop-rollback','StopPipelineExecution',dict(pipelineName=name,pipelineExecutionId=stopped_rb,abandon=True))
        wait(stopped_rb)
        cp('retry-stopped-rollback','RetryStageExecution',dict(pipelineName=name,stageName='Deploy',pipelineExecutionId=stopped_rb,retryMode='ALL_ACTIONS'),False)
        cp('stop-retried-rollback','StopPipelineExecution',dict(pipelineName=name,pipelineExecutionId=stopped_rb,abandon=True),False)
        rollback('unsuccessful-target',running)
        for mode in ('QUEUED','PARALLEL'):
            declaration['executionMode'] = mode
            declaration['stages'][1]['actions'] = declaration['stages'][1]['actions'][:1]
            cp('mode-'+mode,'UpdatePipeline',dict(pipeline=declaration))
            target = wait(start())
            mode_rb = rollback('rollback-mode-'+mode,target,strict=True)['pipelineExecutionId']
            wait(mode_rb)
            snapshot('rollback-mode-'+mode,mode_rb)
        evidence['complete'] = True
    except BaseException as error:
        evidence['failure'] = repr(error)
        raise
    finally:
        failures = []
        if owned['pipeline']:
            try:
                cp('delete-pipeline','DeletePipeline',dict(name=name),cleanup=True)
                cp('verify-pipeline-absent','GetPipeline',dict(name=name),False,True)
            except Exception as error:
                failures.append(repr(error))
        for bucket in owned['buckets']:
            try:
                while True:
                    rows = sdk('s3','list_object_versions',dict(Bucket=bucket),True)
                    objects = [dict(Key=v['Key'],VersionId=v['VersionId']) for k in ('Versions','DeleteMarkers') for v in rows.get(k,[])]
                    if objects:
                        result = sdk('s3','delete_objects',dict(Bucket=bucket,Delete=dict(Objects=objects,Quiet=True)),True)
                        if result.get('Errors'):
                            raise RuntimeError(str(result['Errors']))
                    if not rows.get('IsTruncated'):
                        break
                sdk('s3','delete_bucket',dict(Bucket=bucket),True)
                try:
                    sdk('s3','head_bucket',dict(Bucket=bucket),True)
                    raise RuntimeError('Owned bucket still exists')
                except ClientError as error:
                    if error.response['Error']['Code'] not in ('404','NoSuchBucket'):
                        raise
            except Exception as error:
                failures.append(repr(error))
        if owned['policy']:
            try:
                sdk('iam','delete_role_policy',dict(RoleName=name,PolicyName='owned'),True)
            except Exception as error:
                failures.append(repr(error))
        if owned['role']:
            try:
                sdk('iam','delete_role',dict(RoleName=name),True)
                try:
                    sdk('iam','get_role',dict(RoleName=name),True)
                    raise RuntimeError('Owned role still exists')
                except ClientError as error:
                    if error.response['Error']['Code'] != 'NoSuchEntity':
                        raise
            except Exception as error:
                failures.append(repr(error))
        evidence['cleanup_failures'] = failures
        evidence['cleanup_verified'] = not failures
        save()
        if failures:
            raise RuntimeError(str(failures))

if __name__ == '__main__':
    main()
