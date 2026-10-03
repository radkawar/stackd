#!/usr/bin/env python3
"""Exact-owned native Lambda control and provisioned Init side-effect calibration."""
import argparse
import io
import json
from pathlib import Path
import time
import uuid
import zipfile

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

HANDLER = '''import boto3,json,os,uuid
identity=uuid.uuid4().hex
kind=os.environ['AWS_LAMBDA_INITIALIZATION_TYPE']
queue=boto3.client('sqs')
queue.send_message(QueueUrl=os.environ['QUEUE'],MessageBody=json.dumps({'phase':'init','identity':identity,'kind':kind}))
def handle(event,context):
    queue.send_message(QueueUrl=os.environ['QUEUE'],MessageBody=json.dumps({'phase':'invoke','identity':identity,'kind':kind}))
    return {'identity':identity,'kind':kind}
'''

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--account', required=True, help='AWS account ID that STS must match before native writes')
    parser.add_argument('--output',required=True)
    args=parser.parse_args()
    session=boto3.Session(region_name='us-east-1')
    identity=session.client('sts').get_caller_identity()
    if identity['Account'] != args.account:
        raise RuntimeError('Refusing writes outside the selected account')
    clients={name:session.client(name,config=Config(retries={'total_max_attempts':1})) for name in ('iam','lambda','sqs')}
    iam,fn,sqs=(clients[x] for x in ('iam','lambda','sqs'))
    name='stackd-next-lambda-controls-'+uuid.uuid4().hex[:10]
    report={'account':identity['Account'],'region':'us-east-1','name':name,'observations':{},'cleanup':{}}
    role=queue=function=None
    def capture(label,operation,**params):
        try:
            result=operation(**params)
            if 'Payload' in result: result['Payload']=json.loads(result['Payload'].read())
            report['observations'][label]=result
            return result
        except ClientError as error:
            report['observations'][label]={'Error':error.response['Error'],'ResponseMetadata':error.response['ResponseMetadata']}
            return None
    def wait(operation,label):
        until=time.monotonic()+180
        while time.monotonic()<until:
            result=operation()
            if result: return result
            time.sleep(1)
        raise TimeoutError(label)
    def ready():
        row=fn.get_function_configuration(FunctionName=name)
        if row['State']=='Failed': raise RuntimeError(row)
        return row['State']=='Active'
    def provisioned():
        row=fn.get_provisioned_concurrency_config(FunctionName=name,Qualifier='1')
        if row['Status']=='FAILED': raise RuntimeError(row)
        return row if row['Status']=='READY' else None
    def receive():
        rows=sqs.receive_message(QueueUrl=queue,MaxNumberOfMessages=10,WaitTimeSeconds=1).get('Messages',[])
        for row in rows: sqs.delete_message(QueueUrl=queue,ReceiptHandle=row['ReceiptHandle'])
        return [json.loads(row['Body']) for row in rows]
    try:
        queue=sqs.create_queue(QueueName=name)['QueueUrl']
        arn=sqs.get_queue_attributes(QueueUrl=queue,AttributeNames=['QueueArn'])['Attributes']['QueueArn']
        role=iam.create_role(RoleName=name,AssumeRolePolicyDocument=json.dumps({'Version':'2012-10-17','Statement':[{'Effect':'Allow','Principal':{'Service':'lambda.amazonaws.com'},'Action':'sts:AssumeRole'}]}))['Role']['Arn']
        iam.put_role_policy(RoleName=name,PolicyName='owned',PolicyDocument=json.dumps({'Version':'2012-10-17','Statement':[{'Effect':'Allow','Action':'sqs:SendMessage','Resource':arn}]}))
        archive=io.BytesIO()
        with zipfile.ZipFile(archive,'w') as z: z.writestr('handler.py',HANDLER)
        deadline=time.monotonic()+60
        while True:
            try:
                function=fn.create_function(FunctionName=name,Runtime='python3.12',Role=role,Handler='handler.handle',Code={'ZipFile':archive.getvalue()},Timeout=20,MemorySize=128,Publish=True,Environment={'Variables':{'QUEUE':queue}})['FunctionArn']
                break
            except ClientError as error:
                if error.response['Error']['Code']!='InvalidParameterValueException' or 'assumed' not in str(error) or time.monotonic()>=deadline: raise
                time.sleep(2)
        wait(ready,'function readiness')
        capture('recursion_default',fn.get_function_recursion_config,FunctionName=name)
        capture('recursion_allow',fn.put_function_recursion_config,FunctionName=name,RecursiveLoop='Allow')
        capture('recursion_terminate',fn.put_function_recursion_config,FunctionName=name,RecursiveLoop='Terminate')
        capture('runtime_default',fn.get_runtime_management_config,FunctionName=name)
        capture('runtime_update',fn.put_runtime_management_config,FunctionName=name,UpdateRuntimeOn='FunctionUpdate')
        capture('runtime_auto',fn.put_runtime_management_config,FunctionName=name,UpdateRuntimeOn='Auto')
        capture('provisioned_missing',fn.get_provisioned_concurrency_config,FunctionName=name,Qualifier='1')
        capture('provisioned_latest',fn.put_provisioned_concurrency_config,FunctionName=name,Qualifier='$LATEST',ProvisionedConcurrentExecutions=1)
        capture('provisioned_accept',fn.put_provisioned_concurrency_config,FunctionName=name,Qualifier='1',ProvisionedConcurrentExecutions=1)
        report['observations']['provisioned_ready']=wait(provisioned,'preinitialization')
        report['observations']['before_invoke_side_effects']=wait(receive,'Init SQS effect')
        capture('warm_invoke',fn.invoke,FunctionName=name,Qualifier='1',Payload=b'{}')
        capture('cold_latest',fn.invoke,FunctionName=name,Payload=b'{}')
        report['observations']['invoke_side_effects']=wait(receive,'invoke SQS effects')
        capture('reserved_below_provisioned',fn.put_function_concurrency,FunctionName=name,ReservedConcurrentExecutions=0)
        fn.create_alias(FunctionName=name,Name='live',FunctionVersion='1')
        capture('overlapping_alias',fn.put_provisioned_concurrency_config,FunctionName=name,Qualifier='live',ProvisionedConcurrentExecutions=1)
        capture('provisioned_list',fn.list_provisioned_concurrency_configs,FunctionName=name)
        capture('provisioned_delete',fn.delete_provisioned_concurrency_config,FunctionName=name,Qualifier='1')
        capture('provisioned_after_delete',fn.get_provisioned_concurrency_config,FunctionName=name,Qualifier='1')
    finally:
        if function:
            fn.delete_function(FunctionName=name)
            report['cleanup']['function']=True
        if role:
            iam.delete_role_policy(RoleName=name,PolicyName='owned')
            iam.delete_role(RoleName=name)
            report['cleanup']['role']=True
        if queue:
            sqs.delete_queue(QueueUrl=queue)
            report['cleanup']['queue']=True
        Path(args.output).write_text(json.dumps(report,default=str,indent=2)+'\n')
    print(json.dumps({'name':name,'observations':list(report['observations']),'cleanup':report['cleanup']}))

if __name__=='__main__': main()
