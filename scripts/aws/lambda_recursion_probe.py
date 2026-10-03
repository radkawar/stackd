#!/usr/bin/env python3
"""Bounded native SDK recursion chains with SQS execution effects and exact cleanup."""
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

HANDLER='''import boto3,json,os
functions=boto3.client('lambda')
queue=boto3.client('sqs')
def handle(event,context):
    queue.send_message(QueueUrl=os.environ['QUEUE'],MessageBody=json.dumps({'chain':event['chain'],'n':event['n'],'trace':os.environ.get('_X_AMZN_TRACE_ID','')}))
    if event['n']<18:
        functions.invoke(FunctionName=context.invoked_function_arn,InvocationType='Event',Payload=json.dumps({'chain':event['chain'],'n':event['n']+1}).encode())
    return {'n':event['n']}
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
    fn,iam,sqs=[session.client(name,config=Config(retries={'total_max_attempts':1})) for name in ('lambda','iam','sqs')]
    name='stackd-next-lambda-recursion-'+uuid.uuid4().hex[:10]
    report={'account':identity['Account'],'region':'us-east-1','name':name,'observations':{},'cleanup':{}}
    role=queue=function=None
    def wait(operation,label,timeout=120):
        until=time.monotonic()+timeout
        while time.monotonic()<until:
            result=operation()
            if result:return result
            time.sleep(.5)
        raise TimeoutError(label)
    def chain(mode):
        response=fn.put_function_recursion_config(FunctionName=name,RecursiveLoop=mode)
        report['observations'][mode+'_control']=response
        wait(lambda:fn.get_function_recursion_config(FunctionName=name)['RecursiveLoop']==mode,'recursion mode')
        fn.invoke(FunctionName=name,InvocationType='Event',Payload=json.dumps({'chain':mode,'n':1}).encode())
        rows=[];last=time.monotonic();deadline=last+120
        while time.monotonic()<deadline:
            messages=sqs.receive_message(QueueUrl=queue,MaxNumberOfMessages=10,WaitTimeSeconds=2).get('Messages',[])
            for message in messages:
                value=json.loads(message['Body']);sqs.delete_message(QueueUrl=queue,ReceiptHandle=message['ReceiptHandle'])
                if value['chain']==mode:rows.append(value);last=time.monotonic()
            if rows and time.monotonic()-last>10:break
        report['observations'][mode+'_executions']=sorted(rows,key=lambda row:row['n'])
        assert rows,'no real recursion side effects'
    try:
        queue=sqs.create_queue(QueueName=name)['QueueUrl']
        queuearn=sqs.get_queue_attributes(QueueUrl=queue,AttributeNames=['QueueArn'])['Attributes']['QueueArn']
        role=iam.create_role(RoleName=name,AssumeRolePolicyDocument=json.dumps({'Version':'2012-10-17','Statement':[{'Effect':'Allow','Principal':{'Service':'lambda.amazonaws.com'},'Action':'sts:AssumeRole'}]}))['Role']['Arn']
        iam.put_role_policy(RoleName=name,PolicyName='owned',PolicyDocument=json.dumps({'Version':'2012-10-17','Statement':[{'Effect':'Allow','Action':'sqs:SendMessage','Resource':queuearn},{'Effect':'Allow','Action':'lambda:InvokeFunction','Resource':f'arn:aws:lambda:us-east-1:{args.account}:function:'+name}]}))
        archive=io.BytesIO()
        with zipfile.ZipFile(archive,'w') as z:z.writestr('handler.py',HANDLER)
        until=time.monotonic()+60
        while True:
            try:
                function=fn.create_function(FunctionName=name,Runtime='python3.12',Role=role,Handler='handler.handle',Code={'ZipFile':archive.getvalue()},Timeout=20,MemorySize=128,Environment={'Variables':{'QUEUE':queue}})['FunctionArn'];break
            except ClientError as error:
                if error.response['Error']['Code']!='InvalidParameterValueException' or 'assumed' not in str(error) or time.monotonic()>=until:raise
                time.sleep(2)
        wait(lambda:fn.get_function_configuration(FunctionName=name)['State']=='Active','function readiness')
        chain('Terminate');chain('Allow')
    finally:
        if function:fn.delete_function(FunctionName=name);report['cleanup']['function']=True
        if role:
            iam.delete_role_policy(RoleName=name,PolicyName='owned');iam.delete_role(RoleName=name);report['cleanup']['role']=True
        if queue:sqs.delete_queue(QueueUrl=queue);report['cleanup']['queue']=True
        Path(args.output).write_text(json.dumps(report,default=str,indent=2)+'\n')
    print(json.dumps({'name':name,'counts':{mode:len(report['observations'][mode+'_executions']) for mode in ('Terminate','Allow')},'cleanup':report['cleanup']}))

if __name__=='__main__':main()
