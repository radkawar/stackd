#!/usr/bin/env python3
"""Signed executable manual rollback, actual retained S3 bytes and SQLite restart."""
import argparse
import io
import json
import os
from pathlib import Path
import socket
import urllib.request
import uuid
import zipfile

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError
from stackd_process import StackdProcess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary',type=Path,required=True)
    parser.add_argument('--state-directory',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    args = parser.parse_args()
    state = args.state_directory.resolve()
    state.mkdir(parents=True)
    if args.output.exists():
        raise RuntimeError('Refusing to overwrite evidence')
    with socket.socket() as sock:
        sock.bind(('127.0.0.1',0))
        port = sock.getsockname()[1]
    endpoint = f'http://127.0.0.1:{port}'
    process = StackdProcess(state)
    command = [str(args.binary.resolve()),'-listen',f'127.0.0.1:{port}','-public-endpoint',endpoint,'-database',str(state/'state.sqlite'),'-clock-start','2026-10-01T12:00:00Z']
    env = {k:v for k,v in os.environ.items() if not k.startswith('AWS_')}
    env.update(AWS_ACCESS_KEY_ID='test',AWS_SECRET_ACCESS_KEY='test',AWS_DEFAULT_REGION='us-east-1',AWS_EC2_METADATA_DISABLED='true')
    session = boto3.Session(aws_access_key_id='test',aws_secret_access_key='test',region_name='us-east-1')
    config = Config(retries={'total_max_attempts':1},read_timeout=60,s3={'addressing_style':'path'})
    clients = {s:session.client(s,endpoint_url=endpoint,config=config) for s in ('sts','iam','s3','codepipeline')}
    cp,iam,s3 = clients['codepipeline'],clients['iam'],clients['s3']
    name = 'rollback-smoke-'+uuid.uuid4().hex[:8]
    source,artifacts,dest = [name+'-'+s for s in ('src','artifacts','dst')]
    report = {'controllers':process.runs,'endpoint':endpoint,'name':name,'observations':{},'cleanup':[],'complete':False}
    cleanup = []

    def save():
        args.output.parent.mkdir(parents=True,exist_ok=True)
        args.output.write_text(json.dumps(report,indent=2,default=str)+'\n')

    def require(ok,message):
        if not ok: raise AssertionError(message)

    def control(path,body):
        request = urllib.request.Request(endpoint+path,data=json.dumps(body).encode(),headers={'Content-Type':'application/json'})
        with urllib.request.urlopen(request,timeout=60) as response: return json.load(response)

    def advance():
        control('/_stackd/clock',{'advance':'1s'})
        control('/_stackd/jobs/drain?limit=4096',{})

    def wait(execution,status='Succeeded'):
        for _ in range(60):
            advance()
            out = cp.get_pipeline_execution(pipelineName=name,pipelineExecutionId=execution)['pipelineExecution']
            if out['status'] not in ('InProgress','Stopping'):
                actions = cp.list_action_executions(pipelineName=name,filter={'pipelineExecutionId':execution})['actionExecutionDetails']
                report['observations'][execution] = dict(execution=out,actions=actions)
                save()
                require(out['status']==status,str(out))
                return out,actions
        raise RuntimeError('Execution deadline')

    def negative(label,code,fn):
        try: fn()
        except ClientError as error:
            report['observations'][label] = error.response
            require(error.response['Error']['Code']==code,str(error))
            save(); return
        raise AssertionError(label+' unexpectedly succeeded')

    def upload(value):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf,'w') as z: z.writestr('value.txt',value)
        return s3.put_object(Bucket=source,Key='source.zip',Body=buf.getvalue())['VersionId']

    def body(key):
        result = s3.get_object(Bucket=dest,Key=key)
        with result['Body'] as stream: value = stream.read().decode()
        report['observations'].setdefault('bytes',[]).append(dict(key=key,value=value,version=result.get('VersionId')))
        save(); return value

    def remove_bucket(bucket):
        rows = s3.list_object_versions(Bucket=bucket)
        require(not rows.get('IsTruncated'),'Unexpected cleanup pagination')
        objects = [dict(Key=r['Key'],VersionId=r['VersionId']) for k in ('Versions','DeleteMarkers') for r in rows.get(k,[])]
        if objects: require(not s3.delete_objects(Bucket=bucket,Delete={'Objects':objects}).get('Errors'),'Object cleanup failed')
        s3.delete_bucket(Bucket=bucket)

    try:
        process.start(command,endpoint,environment=env)
        account = clients['sts'].get_caller_identity()['Account']
        role = iam.create_role(RoleName=name,AssumeRolePolicyDocument=json.dumps({'Version':'2012-10-17','Statement':[{'Effect':'Allow','Principal':{'Service':'codepipeline.amazonaws.com'},'Action':'sts:AssumeRole'}]}))['Role']
        cleanup.append(('role',lambda:iam.delete_role(RoleName=name)))
        iam.put_role_policy(RoleName=name,PolicyName='owned',PolicyDocument=json.dumps({'Version':'2012-10-17','Statement':[{'Effect':'Allow','Action':'s3:*','Resource':['arn:aws:s3:::'+b+s for b in (source,artifacts,dest) for s in ('','/*')]}]}))
        cleanup.append(('policy',lambda:iam.delete_role_policy(RoleName=name,PolicyName='owned')))
        for bucket in (source,artifacts,dest):
            s3.create_bucket(Bucket=bucket)
            cleanup.append(('bucket:'+bucket,lambda b=bucket:remove_bucket(b)))
            s3.put_bucket_versioning(Bucket=bucket,VersioningConfiguration={'Status':'Enabled'})
        v1revision = upload('v1\n')
        decl = dict(name=name,roleArn=role['Arn'],pipelineType='V2',executionMode='SUPERSEDED',artifactStore=dict(type='S3',location=artifacts),variables=[dict(name='Release',defaultValue='v1')],stages=[
            dict(name='Source',actions=[dict(name='Source',namespace='Src',actionTypeId=dict(category='Source',owner='AWS',provider='S3',version='1'),configuration=dict(S3Bucket=source,S3ObjectKey='source.zip',PollForSourceChanges='false'),outputArtifacts=[dict(name='SourceZip')])]),
            dict(name='Deploy',actions=[dict(name='Deploy',actionTypeId=dict(category='Deploy',owner='AWS',provider='S3',version='1'),configuration=dict(BucketName=dest,Extract='true',ObjectKey='live',CacheControl='#{variables.Release}'),inputArtifacts=[dict(name='SourceZip')])]),
            dict(name='Downstream',actions=[dict(name='Final',actionTypeId=dict(category='Deploy',owner='AWS',provider='S3',version='1'),configuration=dict(BucketName=dest,Extract='true',ObjectKey='final'),inputArtifacts=[dict(name='SourceZip')])])])
        cp.create_pipeline(pipeline=decl)
        cleanup.append(('pipeline',lambda:cp.delete_pipeline(name=name)))
        v1 = cp.list_pipeline_executions(pipelineName=name)['pipelineExecutionSummaries'][0]['pipelineExecutionId']
        _,first_actions = wait(v1)
        require(body('live/value.txt')=='v1\n','v1 deployment')
        upload('v2\n')
        v2 = cp.start_pipeline_execution(name=name,variables=[dict(name='Release',value='v2')])['pipelineExecutionId']
        wait(v2)
        require(body('live/value.txt')=='v2\n','v2 deployment')
        require(body('final/value.txt')=='v2\n','downstream v2 deployment')
        s3.delete_object(Bucket=source,Key='source.zip',VersionId=v1revision)
        negative('source-v1-deleted','NoSuchVersion',lambda:s3.get_object(Bucket=source,Key='source.zip',VersionId=v1revision))
        # The pipeline role can assume but has no CodePipeline control permission.
        caller_role = iam.create_role(RoleName=name+'-caller',AssumeRolePolicyDocument=json.dumps({'Version':'2012-10-17','Statement':[{'Effect':'Allow','Principal':{'AWS':f'arn:aws:iam::{account}:root'},'Action':'sts:AssumeRole'}]}))['Role']
        cleanup.append(('caller-role',lambda:iam.delete_role(RoleName=name+'-caller')))
        creds = clients['sts'].assume_role(RoleArn=caller_role['Arn'],RoleSessionName='DeniedRollback')['Credentials']
        denied = session.client('codepipeline',endpoint_url=endpoint,config=config,aws_access_key_id=creds['AccessKeyId'],aws_secret_access_key=creds['SecretAccessKey'],aws_session_token=creds['SessionToken'])
        negative('caller-denial','AccessDeniedException',lambda:denied.rollback_stage(pipelineName=name,stageName='Deploy',targetPipelineExecutionId=v1))
        require(len(cp.list_pipeline_executions(pipelineName=name)['pipelineExecutionSummaries'])==2,'denied rollback mutated history')
        negative('missing-stage','StageNotFoundException',lambda:cp.rollback_stage(pipelineName=name,stageName='Missing',targetPipelineExecutionId=v1))
        negative('missing-execution','PipelineExecutionNotFoundException',lambda:cp.rollback_stage(pipelineName=name,stageName='Deploy',targetPipelineExecutionId=str(uuid.uuid4())))
        # Both target lineage and the newly admitted rollback survive restart.
        process.stop(); process.start(command,endpoint,environment=env)
        rb = cp.rollback_stage(pipelineName=name,stageName='Deploy',targetPipelineExecutionId=v1)['pipelineExecutionId']
        process.stop(); process.start(command,endpoint,environment=env)
        run,actions = wait(rb)
        require(rb not in (v1,v2) and run['executionType']=='ROLLBACK','rollback identity/type')
        require(run['rollbackMetadata']['rollbackTargetPipelineExecutionId']==v1,'rollback target')
        require(run['variables']==[dict(name='Release',resolvedValue='v1')],'rollback variables')
        require(run['artifactRevisions'][0]['revisionId']==v1revision,'rollback source revision')
        require([a['stageName'] for a in actions]==['Deploy'],'rollback advanced outside target stage')
        original = next(a for a in first_actions if a['stageName']=='Deploy')['input']['inputArtifacts']
        require(actions[0]['input']['inputArtifacts']==original,'rollback lost original artifact locator')
        require(body('live/value.txt')=='v1\n','rollback did not consume retained v1')
        require(body('final/value.txt')=='v2\n','rollback incorrectly advanced downstream')
        require(s3.head_object(Bucket=dest,Key='live/value.txt')['CacheControl']=='v1','rollback resolved current variables')
        state_view = cp.get_pipeline_state(name=name)
        report['observations']['rollback-state'] = state_view
        owners = {s['stageName']:s['latestExecution']['pipelineExecutionId'] for s in state_view['stageStates']}
        require(owners==dict(Source=v2,Deploy=rb,Downstream=v2),'stage ownership changed')
        negative('rollback-target','UnableToRollbackStageException',lambda:cp.rollback_stage(pipelineName=name,stageName='Deploy',targetPipelineExecutionId=rb))
        # Current IAM still gates effects from previously successful target artifacts.
        iam.put_role_policy(RoleName=name,PolicyName='deny',PolicyDocument=json.dumps({'Version':'2012-10-17','Statement':[{'Effect':'Deny','Action':'s3:PutObject','Resource':'arn:aws:s3:::'+dest+'/*'}]}))
        cleanup.append(('deny-policy',lambda:iam.delete_role_policy(RoleName=name,PolicyName='deny')))
        denied_rb = cp.rollback_stage(pipelineName=name,stageName='Deploy',targetPipelineExecutionId=v1)['pipelineExecutionId']
        wait(denied_rb,'Failed')
        iam.delete_role_policy(RoleName=name,PolicyName='deny'); cleanup.pop()
        cp.retry_stage_execution(pipelineName=name,stageName='Deploy',pipelineExecutionId=denied_rb,retryMode='FAILED_ACTIONS')
        wait(denied_rb)
        process.stop(); process.start(command,endpoint,environment=env)
        require(cp.get_pipeline_execution(pipelineName=name,pipelineExecutionId=denied_rb)['pipelineExecution']['executionType']=='ROLLBACK','restart lost rollback history')
        cp.update_pipeline(pipeline=decl)
        negative('outdated-target','PipelineExecutionOutdatedException',lambda:cp.rollback_stage(pipelineName=name,stageName='Deploy',targetPipelineExecutionId=v1))
        report['complete'] = True
    except BaseException as error:
        report['failure'] = repr(error)
        raise
    finally:
        failures = []
        for label,fn in reversed(cleanup):
            try: fn(); report['cleanup'].append(dict(resource=label,status='deleted'))
            except Exception as error: failures.append(dict(resource=label,error=repr(error)))
        report['cleanup_failures'] = failures
        process.stop()
        report['cleanup_verified'] = not failures and all(r.get('exit')==0 for r in process.runs)
        save()
        if failures: raise RuntimeError(str(failures))

if __name__=='__main__': main()
