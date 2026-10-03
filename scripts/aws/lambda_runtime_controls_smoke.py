#!/usr/bin/env python3
"""Signed controls, real Init/handler SQS effects, recursion, SQLite restart and release."""
import argparse
import concurrent.futures
import io
import json
import os
from pathlib import Path
import socket
import subprocess
import time
import urllib.request
import uuid
import zipfile

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

HANDLER = '''import boto3,json,os,time,uuid
from botocore.config import Config
identity=uuid.uuid4().hex
kind=os.environ['AWS_LAMBDA_INITIALIZATION_TYPE']
kwargs={'endpoint_url':os.environ['PROOF_ENDPOINT'],'config':Config(retries={'total_max_attempts':1})}
queue=boto3.client('sqs',**kwargs)
functions=boto3.client('lambda',**kwargs)
def effect(value):
    queue.send_message(QueueUrl=os.environ['QUEUE'],MessageBody=json.dumps(dict(value,identity=identity,kind=kind)))
effect({'phase':'init'})
def handle(event,context):
    effect({'phase':'invoke','event':event})
    if event.get('sleep'): time.sleep(event['sleep'])
    if 'chain' in event and event['n']<18:
        functions.invoke(FunctionName=context.invoked_function_arn,InvocationType='Event',Payload=json.dumps({'chain':event['chain'],'n':event['n']+1}).encode())
    return {'identity':identity,'kind':kind,'event':event}
'''

def require(value, message):
    if not value: raise AssertionError(message)

class Proof:
    def __init__(self,args):
        self.args=args
        self.state=Path(args.state_directory).resolve()
        self.state.mkdir(parents=True,exist_ok=True)
        require(not (self.state/'runtime.sqlite').exists(),'fresh state required')
        with socket.socket() as sock:
            sock.bind(('127.0.0.1',0)); self.port=sock.getsockname()[1]
        self.endpoint=f'http://127.0.0.1:{self.port}'
        self.name='runtime-controls-'+uuid.uuid4().hex[:10]
        self.process=self.log=None
        self.starts=0
        self.report={'name':self.name,'observations':{},'cleanup':{}}
        self.clients={name:self.client(name) for name in ('lambda','iam','sqs','logs')}
        self.fn,self.iam,self.sqs,self.logs=(self.clients[x] for x in ('lambda','iam','sqs','logs'))
        self.function=self.role=self.queue=None
        self.user=self.access_key=None
    def client(self,service,**credentials):
        return boto3.client(service,endpoint_url=self.endpoint,region_name='us-east-1',config=Config(retries={'total_max_attempts':1},read_timeout=180),**(credentials or {'aws_access_key_id':'test','aws_secret_access_key':'test'}))
    def wait(self,fn,label,timeout=180):
        until=time.monotonic()+timeout
        while time.monotonic()<until:
            value=fn()
            if value: return value
            time.sleep(.15)
        raise TimeoutError(label)
    def start(self):
        self.starts+=1
        self.log=(self.state/f'controller-{self.starts}.log').open('wb')
        env={k:v for k,v in os.environ.items() if not k.startswith('AWS_')}
        env['AWS_EC2_METADATA_DISABLED']='true'
        self.process=subprocess.Popen([str(Path(self.args.binary).resolve()),'-listen',f'0.0.0.0:{self.port}','-public-endpoint',self.endpoint,'-database',str(self.state/'runtime.sqlite'),'-docker-host',self.args.docker_host,'-lambda-telemetry-directory',self.args.telemetry_directory,'-compute-endpoint',f'http://host.docker.internal:{self.port}','-lambda-keep-alive','0'],stdout=self.log,stderr=self.log,env=env)
        def ready():
            require(self.process.poll() is None,'controller exited')
            try:
                with urllib.request.urlopen(self.endpoint+'/_stackd/health',timeout=1) as response: return response.status==200
            except OSError: return False
        self.wait(ready,'controller readiness')
    def stop(self):
        if self.process:
            self.process.terminate(); status=self.process.wait(timeout=90)
            self.report.setdefault('controller_exits',[]).append(status)
            self.process=None
            require(status==0,'controller shutdown failed')
        if self.log: self.log.close(); self.log=None
    def receive(self):
        rows=self.sqs.receive_message(QueueUrl=self.queue,MaxNumberOfMessages=10,WaitTimeSeconds=1).get('Messages',[])
        for row in rows: self.sqs.delete_message(QueueUrl=self.queue,ReceiptHandle=row['ReceiptHandle'])
        return [json.loads(row['Body']) for row in rows]
    def expect_error(self,code,operation,**params):
        try: operation(**params)
        except ClientError as error:
            require(error.response['Error']['Code']==code,str(error))
            return error.response['Error']
        raise AssertionError('expected '+code)
    def provisioned(self,count=1):
        row=self.fn.get_provisioned_concurrency_config(FunctionName=self.name,Qualifier='1')
        require(row['Status']!='FAILED',str(row))
        return row if row['Status']=='READY' and row['AllocatedProvisionedConcurrentExecutions']==count and row['AvailableProvisionedConcurrentExecutions']==count else None
    def invoke(self,event=None,qualifier='1'):
        params={'FunctionName':self.name,'Payload':json.dumps(event or {}).encode()}
        if qualifier: params['Qualifier']=qualifier
        row=self.fn.invoke(**params)
        payload=json.loads(row['Payload'].read())
        require('FunctionError' not in row,str(payload))
        return payload
    def chain(self,label):
        self.invoke({'chain':label,'n':1})
        seen=[]
        last=time.monotonic()
        until=last+90
        while time.monotonic()<until:
            rows=self.receive()
            for row in rows:
                if row.get('event',{}).get('chain')==label: seen.append(row['event']['n']); last=time.monotonic()
            if seen and time.monotonic()-last>4: break
        return sorted(seen)
    def run(self):
        self.start()
        try:
            self.queue=self.sqs.create_queue(QueueName=self.name)['QueueUrl']
            queuearn=self.sqs.get_queue_attributes(QueueUrl=self.queue,AttributeNames=['QueueArn'])['Attributes']['QueueArn']
            self.role=self.iam.create_role(RoleName=self.name,AssumeRolePolicyDocument=json.dumps({'Version':'2012-10-17','Statement':[{'Effect':'Allow','Principal':{'Service':'lambda.amazonaws.com'},'Action':'sts:AssumeRole'}]}))['Role']['Arn']
            self.iam.put_role_policy(RoleName=self.name,PolicyName='runtime',PolicyDocument=json.dumps({'Version':'2012-10-17','Statement':[{'Effect':'Allow','Action':'sqs:SendMessage','Resource':queuearn},{'Effect':'Allow','Action':'lambda:InvokeFunction','Resource':f'arn:aws:lambda:us-east-1:000000000000:function:{self.name}*'}]}))
            archive=io.BytesIO()
            with zipfile.ZipFile(archive,'w') as z: z.writestr('handler.py',HANDLER)
            self.function=self.fn.create_function(FunctionName=self.name,Runtime='python3.12',Role=self.role,Handler='handler.handle',Code={'ZipFile':archive.getvalue()},Timeout=30,MemorySize=128,Publish=True,Environment={'Variables':{'QUEUE':self.queue.replace('127.0.0.1','host.docker.internal'),'PROOF_ENDPOINT':f'http://host.docker.internal:{self.port}'}})['FunctionArn']
            self.wait(lambda:self.fn.get_function_configuration(FunctionName=self.name)['State']=='Active','function readiness')
            self.user=self.name+'-caller'
            self.iam.create_user(UserName=self.user)
            credentials=self.iam.create_access_key(UserName=self.user)['AccessKey']
            self.access_key=credentials['AccessKeyId']
            caller=self.client('lambda',aws_access_key_id=credentials['AccessKeyId'],aws_secret_access_key=credentials['SecretAccessKey'])
            self.report['observations']['iam_denied']=self.expect_error('AccessDeniedException',caller.put_function_recursion_config,FunctionName=self.name,RecursiveLoop='Allow')
            self.iam.put_user_policy(UserName=self.user,PolicyName='controls',PolicyDocument=json.dumps({'Version':'2012-10-17','Statement':[{'Effect':'Allow','Action':['lambda:GetFunctionRecursionConfig','lambda:PutFunctionRecursionConfig'],'Resource':self.function}]}))
            require(caller.get_function_recursion_config(FunctionName=self.name)['RecursiveLoop']=='Terminate','scoped IAM read')
            caller.put_function_recursion_config(FunctionName=self.name,RecursiveLoop='Terminate')
            self.report['observations']['iam_authorized']=True
            require(self.fn.get_function_recursion_config(FunctionName=self.name)['RecursiveLoop']=='Terminate','recursion default')
            self.fn.put_runtime_management_config(FunctionName=self.name,UpdateRuntimeOn='FunctionUpdate')
            self.report['observations']['manual_prerequisite']=self.expect_error('NotImplementedException',self.fn.put_runtime_management_config,FunctionName=self.name,UpdateRuntimeOn='Manual',RuntimeVersionArn='arn:aws:lambda:us-east-1::runtime:'+('a'*64))
            self.report['observations']['latest_rejected']=self.expect_error('InvalidParameterValueException',self.fn.put_provisioned_concurrency_config,FunctionName=self.name,Qualifier='$LATEST',ProvisionedConcurrentExecutions=1)
            self.fn.put_function_concurrency(FunctionName=self.name,ReservedConcurrentExecutions=1)
            self.fn.put_provisioned_concurrency_config(FunctionName=self.name,Qualifier='1',ProvisionedConcurrentExecutions=1)
            self.report['observations']['ready']=self.wait(self.provisioned,'real Init readiness')
            before=self.wait(self.receive,'Init external effect')
            require(all(row['phase']=='init' for row in before),'handler invoked during prewarming')
            warm=[row for row in before if row['kind']=='provisioned-concurrency']
            require(len(warm)==1,'expected one actual provisioned Init')
            first=self.invoke(); second=self.invoke()
            require(first['identity']==warm[0]['identity']==second['identity'],'preinitialized runtime not reused')
            self.report['observations']['warm_identity']=[warm[0],first,second]
            cold=self.invoke(qualifier='')
            require(cold['kind']=='on-demand' and cold['identity']!=first['identity'],'unqualified invocation stole provisioned environment')
            self.report['observations']['cold_latest']=cold
            self.report['observations']['reservation_protection']=self.expect_error('InvalidParameterValueException',self.fn.put_function_concurrency,FunctionName=self.name,ReservedConcurrentExecutions=0)
            while self.receive(): pass
            self.fn.put_function_concurrency(FunctionName=self.name,ReservedConcurrentExecutions=2)
            self.fn.put_provisioned_concurrency_config(FunctionName=self.name,Qualifier='1',ProvisionedConcurrentExecutions=2)
            self.wait(lambda:self.provisioned(2),'scaled preinitialization')
            initialized=[]
            def two_inits():
                initialized.extend(row for row in self.receive() if row['phase']=='init' and row['kind']=='provisioned-concurrency')
                return len(initialized)==2
            self.wait(two_inits,'two real Init effects')
            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
                calls=[pool.submit(self.invoke,{'sleep':1}) for _ in range(2)]
                simultaneous=[call.result() for call in calls]
            require({row['identity'] for row in simultaneous}=={row['identity'] for row in initialized},'scaled pool did not execute on both preinitialized environments')
            self.fn.put_provisioned_concurrency_config(FunctionName=self.name,Qualifier='1',ProvisionedConcurrentExecutions=1)
            self.wait(self.provisioned,'scaledown readiness')
            self.fn.put_function_concurrency(FunctionName=self.name,ReservedConcurrentExecutions=1)
            first=self.invoke()
            self.report['observations']['scaling']={'init':initialized,'concurrent_invokes':simultaneous,'scaledown':first}
            self.fn.put_function_recursion_config(FunctionName=self.name,RecursiveLoop='Terminate')
            terminated=self.chain('terminate')
            require(terminated==list(range(1,17)),'actual recursion guard did not stop invocation 17: '+str(terminated))
            self.fn.put_function_recursion_config(FunctionName=self.name,RecursiveLoop='Allow')
            allowed=self.chain('allow')
            require(allowed==list(range(1,19)),'Allow failed to affect execution: '+str(allowed))
            self.report['observations']['recursion']={'terminate':terminated,'allow':allowed}
            while self.receive(): pass
            self.stop(); self.start()
            require(self.fn.get_function_recursion_config(FunctionName=self.name)['RecursiveLoop']=='Allow','recursion lost at restart')
            require(self.fn.get_runtime_management_config(FunctionName=self.name)['UpdateRuntimeOn']=='FunctionUpdate','runtime mode lost at restart')
            self.wait(self.provisioned,'restart warm pool recovery')
            init=self.wait(self.receive,'restart Init effect')
            after=self.invoke()
            require(after['kind']=='provisioned-concurrency' and after['identity']!=first['identity'] and any(row['identity']==after['identity'] and row['phase']=='init' for row in init),'restart falsely reused lost environment')
            self.report['observations']['restart']={'init':init,'invoke':after}
            self.fn.delete_provisioned_concurrency_config(FunctionName=self.name,Qualifier='1')
            self.expect_error('ProvisionedConcurrencyConfigNotFoundException',self.fn.get_provisioned_concurrency_config,FunctionName=self.name,Qualifier='1')
            released=self.invoke()
            require(released['kind']=='on-demand' and released['identity']!=after['identity'],'deleted capacity was reused')
            self.report['observations']['released']=released
            self.fn.put_function_concurrency(FunctionName=self.name,ReservedConcurrentExecutions=0)
            self.report['observations']['reserved_zero']=self.expect_error('TooManyRequestsException',self.fn.invoke,FunctionName=self.name,Qualifier='1',Payload=b'{}')
            self.fn.delete_function_concurrency(FunctionName=self.name)
            self.invoke()
            self.fn.delete_function(FunctionName=self.name)
            self.function=None
            self.expect_error('ResourceNotFoundException',self.fn.get_function_recursion_config,FunctionName=self.name)
            self.function=self.fn.create_function(FunctionName=self.name,Runtime='python3.12',Role=self.role,Handler='handler.handle',Code={'ZipFile':archive.getvalue()},Timeout=30,MemorySize=128,Environment={'Variables':{'QUEUE':self.queue.replace('127.0.0.1','host.docker.internal'),'PROOF_ENDPOINT':f'http://host.docker.internal:{self.port}'}})['FunctionArn']
            self.wait(lambda:self.fn.get_function_configuration(FunctionName=self.name)['State']=='Active','recreated function readiness')
            require(self.fn.get_function_recursion_config(FunctionName=self.name)['RecursiveLoop']=='Terminate','deleted recursion policy resurrected')
            require(self.fn.get_runtime_management_config(FunctionName=self.name)['UpdateRuntimeOn']=='Auto','deleted runtime policy resurrected')
            require(self.fn.list_provisioned_concurrency_configs(FunctionName=self.name)['ProvisionedConcurrencyConfigs']==[],'deleted warm capacity resurrected')
            recreated=self.invoke(qualifier='')
            require(recreated['kind']=='on-demand','recreated function inherited provisioned runtime')
            self.report['observations']['recreated']=recreated
        finally:
            try:
                if self.function: self.fn.delete_function(FunctionName=self.name); self.report['cleanup']['function']=True
                if self.queue: self.sqs.delete_queue(QueueUrl=self.queue); self.report['cleanup']['queue']=True
                if self.role:
                    self.iam.delete_role_policy(RoleName=self.name,PolicyName='runtime'); self.iam.delete_role(RoleName=self.name); self.report['cleanup']['role']=True
                if self.user:
                    self.iam.delete_user_policy(UserName=self.user,PolicyName='controls')
                    if self.access_key: self.iam.delete_access_key(UserName=self.user,AccessKeyId=self.access_key)
                    self.iam.delete_user(UserName=self.user); self.report['cleanup']['caller']=True
            finally:
                self.stop()
                (self.state/'report.json').write_text(json.dumps(self.report,default=str,indent=2)+'\n')
        print(json.dumps({'report':str(self.state/'report.json'),'observations':list(self.report['observations']),'cleanup':self.report['cleanup']}))

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--binary',required=True)
    parser.add_argument('--telemetry-directory',required=True)
    parser.add_argument('--state-directory',required=True)
    parser.add_argument('--docker-host',default='unix:///var/run/docker.sock')
    Proof(parser.parse_args()).run()

if __name__=='__main__': main()
