#!/usr/bin/env python3
"""Actual local HTTP -> retained ALB metrics -> managed alarms -> ECS replicas.

Starts the assembled executable on an owned SQLite file, restarts it, and removes
exact-owned native resources through public APIs. No native AWS calls.
"""
import argparse
import concurrent.futures
import datetime
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from dns_http_client import create_connection, opener as dns_opener
from stackd_process import StackdProcess

SERVER = r'''const http=require('http');http.createServer((q,s)=>{if(q.url==='/stall'){setTimeout(()=>s.end('late'),2500);return;}if(q.url==='/stream'){s.writeHead(200);let n=0;let timer=setInterval(()=>{s.write('chunk-'+(++n)+'\n');if(n===12){clearInterval(timer);s.end();}},250);return;}s.end('actual-alb-ecs\n');}).listen(8080,'0.0.0.0');'''

class Smoke:
    def __init__(self,args):
        self.args=args
        self.work=Path(tempfile.mkdtemp(prefix='stackd-alb-scaling-'))
        sock=socket.socket();sock.bind(('127.0.0.1',0));self.port=sock.getsockname()[1];sock.close()
        sock=socket.socket();sock.bind(('127.0.0.1',0));self.dns_endpoint='127.0.0.1:'+str(sock.getsockname()[1]);sock.close()
        self.endpoint='http://127.0.0.1:'+str(self.port)
        self.controller=StackdProcess(self.work)
        self.data={'account':'819230000001','vpc_cidr':'10.230.0.0/23','work':str(self.work),'endpoint':self.endpoint,'owned':{},'observations':[],'controllers':self.controller.runs,'cleanup':{}}
        session=boto3.Session(aws_access_key_id='test',aws_secret_access_key='test',region_name='us-east-1')
        config=Config(retries={'total_max_attempts':1},connect_timeout=5,read_timeout=60)
        self.clients={name:session.client(name,endpoint_url=self.endpoint,config=config) for name in ('ec2','ecs','elbv2','application-autoscaling','cloudwatch','iam')}
        self.http=dns_opener(self.dns_endpoint)
        self.save()
    def save(self):self.args.output.parent.mkdir(parents=True,exist_ok=True);self.args.output.write_text(json.dumps(self.data,indent=2,default=str)+'\n')
    def own(self,name,value):self.data['owned'][name]=value;self.save();return value
    def record(self,label,**values):self.data['observations'].append(dict(label=label,**values));self.save();print(label+': '+json.dumps(values,default=str),flush=True)
    def call(self,kind,method,**parameters):return getattr(self.clients[kind],method)(**parameters)
    def start(self):
        command=[str(self.args.binary),'-listen','0.0.0.0:'+str(self.port),'-dns-listen',self.dns_endpoint,'-database',str(self.work/'state.sqlite'),'-account-id','819230000001','-clock-start','2026-09-27T12:00:00Z','-docker-host',os.environ.get('DOCKER_HOST','unix:///var/run/docker.sock'),'-ecs-runtime','-compute-endpoint','http://host.docker.internal:'+str(self.port),'-elbv2-node-executable',str(self.args.relay)]
        self.controller.start(command,self.endpoint,environment=os.environ,timeout=30)
        self.now()
    def now(self):
        with self.http.open(self.endpoint+'/_stackd/clock',timeout=5) as r:return json.load(r)['time']
    def tick(self,seconds=1):
        body=json.dumps({'advance':str(seconds)+'s'}).encode()
        with self.http.open(urllib.request.Request(self.endpoint+'/_stackd/clock',data=body,headers={'Content-Type':'application/json'}),timeout=30) as r:json.load(r)
        with self.http.open(urllib.request.Request(self.endpoint+'/_stackd/jobs/drain?limit=256',data=b''),timeout=30) as r:json.load(r)
        time.sleep(.3)
    def wait(self,label,fn,attempts=180):
        for _ in range(attempts):
            value=fn()
            if value:return value
            self.tick()
        raise RuntimeError(label+' timed out')
    def service(self):return self.call('ecs','describe_services',cluster=self.data['owned']['cluster'],services=[self.data['owned']['service']])['services'][0]
    def tasks(self):
        o=self.data['owned'];arns=self.call('ecs','list_tasks',cluster=o['cluster'],serviceName=o['service'])['taskArns']
        if not arns:return []
        known=set(o.get('tasks',[]));known.update(arns);self.own('tasks',sorted(known))
        tasks=self.call('ecs','describe_tasks',cluster=o['cluster'],tasks=arns)['tasks']
        enis=set(o.get('enis',[]));containers=set(o.get('containers',[]))
        for task in tasks:
            for attachment in task.get('attachments',[]):
                for detail in attachment.get('details',[]):
                    if detail['name']=='networkInterfaceId':enis.add(detail['value'])
            for container in task.get('containers',[]):
                if container.get('runtimeId'):containers.add(container['runtimeId'])
        self.own('enis',sorted(enis));self.own('containers',sorted(containers));return tasks
    def health(self):return self.call('elbv2','describe_target_health',TargetGroupArn=self.data['owned']['tg'])['TargetHealthDescriptions']
    def ready(self,count):
        service=self.service();tasks=self.tasks();health=self.health()
        return service['desiredCount']==count and service['runningCount']==count and len([x for x in health if x['TargetHealth']['State']=='healthy'])==count and all(d.get('rolloutState')=='COMPLETED' for d in service['deployments'])
    def get(self,path='/'):
        with self.http.open('http://'+self.data['owned']['dns']+path,timeout=10) as r:return r.status,r.read().decode()
    def metrics(self,name,stat='Sum',start=None):
        o=self.data['owned'];now=datetime.datetime.fromisoformat(self.now().replace('Z','+00:00'))
        return self.call('cloudwatch','get_metric_statistics',Namespace='AWS/ApplicationELB',MetricName=name,Dimensions=[dict(Name='LoadBalancer',Value=o['lb'].split(':loadbalancer/')[1]),dict(Name='TargetGroup',Value=o['tg'].split(':')[-1])],StartTime=start or now-datetime.timedelta(hours=1),EndTime=now,Period=60,Statistics=[stat])['Datapoints']
    def minute(self):
        current=datetime.datetime.fromisoformat(self.now().replace('Z','+00:00'));self.tick(60-current.second)
    def run(self):
        self.start();o=self.data['owned'];prefix='alb-scaling-230'
        vpc=self.own('vpc',self.call('ec2','create_vpc',CidrBlock='10.230.0.0/23')['Vpc']['VpcId'])
        subs=[]
        for cidr,zone in [('10.230.0.0/24','us-east-1a'),('10.230.1.0/24','us-east-1b')]:subs.append(self.call('ec2','create_subnet',VpcId=vpc,CidrBlock=cidr,AvailabilityZone=zone)['Subnet']['SubnetId']);self.own('subnets',subs)
        gateway=self.own('gateway',self.call('ec2','create_internet_gateway')['InternetGateway']['InternetGatewayId']);self.call('ec2','attach_internet_gateway',InternetGatewayId=gateway,VpcId=vpc)
        route=self.own('route',self.call('ec2','describe_route_tables',Filters=[dict(Name='vpc-id',Values=[vpc])])['RouteTables'][0]['RouteTableId']);self.call('ec2','create_route',RouteTableId=route,DestinationCidrBlock='0.0.0.0/0',GatewayId=gateway)
        sg=self.own('sg',self.call('ec2','create_security_group',VpcId=vpc,GroupName=prefix,Description=prefix)['GroupId']);self.call('ec2','authorize_security_group_ingress',GroupId=sg,IpPermissions=[dict(IpProtocol='tcp',FromPort=80,ToPort=8080,IpRanges=[dict(CidrIp='0.0.0.0/0')])])
        lb=self.call('elbv2','create_load_balancer',Name=prefix,Subnets=subs,SecurityGroups=[sg],Scheme='internet-facing',Type='application')['LoadBalancers'][0];self.own('lb',lb['LoadBalancerArn'])
        self.call('elbv2','modify_load_balancer_attributes',LoadBalancerArn=o['lb'],Attributes=[dict(Key='idle_timeout.timeout_seconds',Value='1')])
        tg=self.own('tg',self.call('elbv2','create_target_group',Name=prefix,Protocol='HTTP',Port=8080,VpcId=vpc,TargetType='ip',HealthCheckIntervalSeconds=5,HealthCheckTimeoutSeconds=2,HealthyThresholdCount=2,UnhealthyThresholdCount=2)['TargetGroups'][0]['TargetGroupArn'])
        self.call('elbv2','modify_target_group_attributes',TargetGroupArn=tg,Attributes=[dict(Key='deregistration_delay.timeout_seconds',Value='5')])
        self.own('listener',self.call('elbv2','create_listener',LoadBalancerArn=o['lb'],Protocol='HTTP',Port=80,DefaultActions=[dict(Type='forward',TargetGroupArn=tg)])['Listeners'][0]['ListenerArn'])
        self.own('cluster',self.call('ecs','create_cluster',clusterName=prefix)['cluster']['clusterName'])
        self.own('definition',self.call('ecs','register_task_definition',family=prefix,networkMode='awsvpc',requiresCompatibilities=['FARGATE'],cpu='256',memory='512',containerDefinitions=[dict(name='web',image='node:22-alpine',essential=True,entryPoint=['node'],command=['-e',SERVER],portMappings=[dict(containerPort=8080)])])['taskDefinition']['taskDefinitionArn'])
        self.own('service',prefix);self.call('ecs','create_service',cluster=o['cluster'],serviceName=prefix,taskDefinition=o['definition'],desiredCount=1,launchType='FARGATE',networkConfiguration=dict(awsvpcConfiguration=dict(subnets=[subs[0]],securityGroups=[sg])),loadBalancers=[dict(targetGroupArn=tg,containerName='web',containerPort=8080)],healthCheckGracePeriodSeconds=30)
        self.wait('healthy replica',lambda:self.ready(1))
        def balancer_ready():
            current=self.call('elbv2','describe_load_balancers',LoadBalancerArns=[o['lb']])['LoadBalancers'][0]
            return current if current.get('DNSName') and current['State']['Code']=='active' else None
        lb=self.wait('active ALB and native address',balancer_ready);self.own('dns',lb['DNSName'])
        self.record('initial-native-http',response=self.get(),health=self.health())
        self.minute();start=datetime.datetime.fromisoformat(self.now().replace('Z','+00:00'))
        for _ in range(12):assert self.get()==(200,'actual-alb-ecs\n')
        before=self.tasks();ids=[c['runtimeId'] for t in before for c in t['containers']]
        inspect_before=json.loads(subprocess.check_output(['docker','inspect',*ids]))
        self.controller.stop(timeout=45,kill_on_timeout=True);self.start();self.wait('recovered healthy replica',lambda:self.ready(1))
        after=self.tasks();ids_after=[c['runtimeId'] for t in after for c in t['containers']]
        inspect_after=json.loads(subprocess.check_output(['docker','inspect',*ids_after]))
        assert ids==ids_after
        assert [(x['State']['Pid'],x['State']['StartedAt']) for x in inspect_before]==[(x['State']['Pid'],x['State']['StartedAt']) for x in inspect_after]
        self.minute();counts=self.metrics('RequestCountPerTarget',start=start)
        assert sum(x['Sum'] for x in counts)==12,counts
        self.record('restart-retained-real-request-window',metric=counts,containers=ids,processes=[x['State'] for x in inspect_after])
        failures=[]
        def recovered_http():
            try:return self.get()==(200,'actual-alb-ecs\n')
            except Exception as error:failures.append(repr(error));return False
        self.wait('actual post-restart ALB HTTP',recovered_http)
        self.record('post-restart-native-http',readiness_failures=failures)
        self.record('stream-under-one-second-idle',response=self.get('/stream'))
        raw=create_connection(self.dns_endpoint,(o['dns'],80),timeout=5);raw.sendall(b'GET / HTTP/1.1\r\nHost: partial');status=raw.recv(100).split(b'\r\n')[0].decode();raw.close();assert '408' in status;self.record('incomplete-header-idle',status=status)
        resource=self.own('resource','service/'+o['cluster']+'/'+o['service'])
        self.call('application-autoscaling','register_scalable_target',ServiceNamespace='ecs',ResourceId=resource,ScalableDimension='ecs:service:DesiredCount',MinCapacity=1,MaxCapacity=2)
        capture=json.loads((Path(__file__).resolve().parents[2]/'testdata/aws/applicationautoscaling/alb_policy_bound_native.json').read_text())
        native_alarms=next(x['output']['MetricAlarms'] for x in capture['calls'] if x['label']=='alarms-bound')
        replay=[]
        for row in capture['calls']:
            if not row['label'].startswith('policy-'):continue
            parameters=json.loads(json.dumps(row['input']))
            parameters['ResourceId']=resource
            specification=parameters['TargetTrackingScalingPolicyConfiguration']['PredefinedMetricSpecification']
            specification['ResourceLabel']=specification['ResourceLabel'].replace(capture['owned']['source_lb'].split(':loadbalancer/')[1],o['lb'].split(':loadbalancer/')[1]).replace(capture['owned']['tg'].split(':')[-1],tg.split(':')[-1])
            try:
                accepted=self.call('application-autoscaling','put_scaling_policy',**parameters)
                assert row['code']=='Success',row
                alarms=self.call('cloudwatch','describe_alarms',AlarmNames=[a['AlarmName'] for a in accepted['Alarms']])['MetricAlarms']
                for actual in alarms:
                    expected=next(a for a in native_alarms if a['ComparisonOperator']==actual['ComparisonOperator'])
                    for field in ['Namespace','MetricName','Statistic','Unit','Period','EvaluationPeriods','Threshold']:assert actual[field]==expected[field],(field,actual,expected)
                self.call('application-autoscaling','delete_scaling_policy',ServiceNamespace='ecs',ResourceId=resource,ScalableDimension='ecs:service:DesiredCount',PolicyName=parameters['PolicyName'])
                replay.append(dict(label=row['label'],code='Success'))
            except ClientError as error:
                assert error.response['Error']['Code']==row['code'],(row,error)
                replay.append(dict(label=row['label'],code=error.response['Error']['Code']))
        self.record('native-policy-fixture-replay',cases=replay)
        policy=self.call('application-autoscaling','put_scaling_policy',ServiceNamespace='ecs',ResourceId=resource,ScalableDimension='ecs:service:DesiredCount',PolicyName='requests',PolicyType='TargetTrackingScaling',TargetTrackingScalingPolicyConfiguration=dict(TargetValue=20,ScaleInCooldown=0,ScaleOutCooldown=0,PredefinedMetricSpecification=dict(PredefinedMetricType='ALBRequestCountPerTarget',ResourceLabel=o['lb'].split(':loadbalancer/')[1]+'/'+tg.split(':')[-1])))
        self.own('alarms',[x['AlarmName'] for x in policy['Alarms']]);self.record('native-managed-alarm-mapping',alarms=self.call('cloudwatch','describe_alarms',AlarmNames=o['alarms'])['MetricAlarms'])
        for minute in range(7):
            for _ in range(60):assert self.get()[0]==200
            self.minute();self.record('request-minute-'+str(minute),service=self.service(),metric=self.metrics('RequestCountPerTarget'))
            if self.service()['desiredCount']==2:break
        assert self.service()['desiredCount']==2
        self.wait('scale-out healthy completion',lambda:self.ready(2));expanded=self.tasks();self.record('scale-out-real-replicas',tasks=expanded,health=self.health(),activities=self.call('application-autoscaling','describe_scaling_activities',ServiceNamespace='ecs',ResourceId=resource)['ScalingActivities'])
        for minute in range(20):
            self.minute();self.tasks()
            if self.service()['desiredCount']==1:break
        assert self.service()['desiredCount']==1
        self.record('scale-in-intent',service=self.service(),health=self.health())
        self.wait('scale-in healthy completion',lambda:self.ready(1))
        retired=[t['taskArn'] for t in expanded if t['taskArn'] not in [x['taskArn'] for x in self.tasks()]]
        def retired_stopped():return all(t['lastStatus']=='STOPPED' for t in self.call('ecs','describe_tasks',cluster=o['cluster'],tasks=retired)['tasks'])
        self.wait('retired tasks truly stopped',retired_stopped)
        stopped=self.call('ecs','describe_tasks',cluster=o['cluster'],tasks=retired)['tasks'];self.record('scale-in-real-termination',tasks=stopped,health=self.health(),metric=self.metrics('RequestCountPerTarget'),activities=self.call('application-autoscaling','describe_scaling_activities',ServiceNamespace='ecs',ResourceId=resource)['ScalingActivities'])
        self.data['behavior_passed']=True;self.save()
    def cleanup(self):
        o=self.data['owned'];errors=[]
        if self.controller.process is None:self.start()
        def step(label,kind,method,**parameters):
            try:self.call(kind,method,**parameters);self.data['cleanup'][label]=True
            except Exception as error:errors.append(dict(step=label,error=repr(error)))
            self.save()
        if o.get('resource'):step('scalable-target','application-autoscaling','deregister_scalable_target',ServiceNamespace='ecs',ResourceId=o['resource'],ScalableDimension='ecs:service:DesiredCount')
        if o.get('service'):
            self.tasks();step('scale-to-zero','ecs','update_service',cluster=o['cluster'],service=o['service'],desiredCount=0)
            if o.get('tasks'):
                self.wait('all owned tasks stopped',lambda:all(t['lastStatus']=='STOPPED' for t in self.call('ecs','describe_tasks',cluster=o['cluster'],tasks=o['tasks'])['tasks']))
                self.record('cleanup-actual-stopped',tasks=self.call('ecs','describe_tasks',cluster=o['cluster'],tasks=o['tasks'])['tasks'])
            step('service-delete','ecs','delete_service',cluster=o['cluster'],service=o['service'],force=True)
        if o.get('lb'):
            step('alb-delete','elbv2','delete_load_balancer',LoadBalancerArn=o['lb'])
            try:self.call('elbv2','describe_load_balancers',LoadBalancerArns=[o['lb']]);raise AssertionError('logical ALB remains')
            except ClientError as error:assert error.response['Error']['Code']=='LoadBalancerNotFound'
            self.record('logical-alb-absence-before-release',interfaces=self.call('ec2','describe_network_interfaces',Filters=[dict(Name='vpc-id',Values=[o['vpc']])])['NetworkInterfaces'])
            self.wait('managed interfaces retired',lambda:not self.call('ec2','describe_network_interfaces',Filters=[dict(Name='vpc-id',Values=[o['vpc']])])['NetworkInterfaces'])
        if o.get('tg'):step('target-group-delete','elbv2','delete_target_group',TargetGroupArn=o['tg'])
        if o.get('definition'):
            step('definition-inactive','ecs','deregister_task_definition',taskDefinition=o['definition']);step('definition-delete','ecs','delete_task_definitions',taskDefinitions=[o['definition']])
        if o.get('cluster'):step('cluster-delete','ecs','delete_cluster',cluster=o['cluster'])
        if o.get('sg'):step('security-group-delete','ec2','delete_security_group',GroupId=o['sg'])
        for subnet in o.get('subnets',[]):step('subnet-delete-'+subnet,'ec2','delete_subnet',SubnetId=subnet)
        if o.get('gateway'):
            step('gateway-detach','ec2','detach_internet_gateway',InternetGatewayId=o['gateway'],VpcId=o['vpc']);step('gateway-delete','ec2','delete_internet_gateway',InternetGatewayId=o['gateway'])
        if o.get('vpc'):step('vpc-delete','ec2','delete_vpc',VpcId=o['vpc'])
        self.data['cleanup']['errors']=errors
        for container in o.get('containers',[]):
            result=subprocess.run(['docker','inspect',container],capture_output=True,text=True);assert result.returncode!=0
        owned_networks=subprocess.check_output(['docker','network','ls','--filter','label=stackd.ecs.network','--format','{{.ID}} {{.Name}}']).decode().splitlines()
        remaining=[]
        for item in owned_networks:
            network=json.loads(subprocess.check_output(['docker','network','inspect',item.split()[0]]))[0]
            if any(config.get('Subnet')=='10.230.0.0/23' for config in network.get('IPAM',{}).get('Config',[])):remaining.append(network['Id'])
        alb_nodes=subprocess.check_output(['docker','ps','-aq','--filter','label=stackd.elbv2.load-balancer='+o.get('lb','not-owned')]).decode().splitlines()
        self.data['cleanup'].update(remaining_owned_networks=remaining,remaining_alb_containers=alb_nodes);self.save();assert not errors and not remaining and not alb_nodes

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--binary',type=Path,required=True);parser.add_argument('--relay',type=Path,required=True);parser.add_argument('--output',type=Path,required=True);args=parser.parse_args();smoke=Smoke(args)
    try:smoke.run()
    finally:
        try:smoke.cleanup()
        finally:
            try:smoke.controller.stop(timeout=45,kill_on_timeout=True)
            finally:smoke.save()
