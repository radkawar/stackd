#!/usr/bin/env python3
"""Bounded owned ALB request metrics/policy capture; one ALB and t3.micro.

Uses read-only placement in the approved VPC. All writes belong to the unique
probe; SIGINT/SIGTERM/deadline enter exact cleanup, resumable with --cleanup-only.
"""
import argparse
import datetime
import json
from pathlib import Path
import signal
import time
import urllib.request
import urllib.error
import uuid

from ebs_encryption_probe import Capture, CONFIG, now
from cloudtrail_events import collect_history

VPC = "vpc-0aeae393af73839cf"
SUBNETS = ["subnet-07acfd804ed04876f", "subnet-04330c3b0ad66039a"]
DOCS = ["https://docs.aws.amazon.com/elasticloadbalancing/latest/application/load-balancer-cloudwatch-metrics.html", "https://docs.aws.amazon.com/autoscaling/application/APIReference/API_PredefinedMetricSpecification.html"]
USER_DATA = '''#!/bin/bash
cat >/tmp/alb-server.py <<'PY'
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import threading, time
class Handler(BaseHTTPRequestHandler):
 def do_GET(self):
  if self.path == '/slow': time.sleep(2)
  code = 500 if self.path == '/error' else 200
  body = b'owned-alb-metric-target\\n'
  self.send_response(code); self.send_header('Content-Length', str(len(body))); self.end_headers(); self.wfile.write(body)
for port in [8080,8081]:
 threading.Thread(target=ThreadingHTTPServer(('0.0.0.0',port),Handler).serve_forever,daemon=True).start()
while True: time.sleep(60)
PY
python3 /tmp/alb-server.py >/tmp/alb-server.log 2>&1 &
'''

class Probe(Capture):
    def __init__(self, args):
        super().__init__(args)
        for name in ('elbv2', 'ecs', 'application-autoscaling', 'cloudwatch', 'ssm'):
            self.clients[name] = self.session.client(name, config=CONFIG)
        if not args.cleanup_only and not args.audit_only:
            self.data.update(prefix='stackd-albm-' + uuid.uuid4().hex[:10], documentation=DOCS,
                scope='One owned t3.micro/8-GiB gp3 root and one ALB, owned security group/target groups/ECS zero-replica service; existing VPC/subnets are read-only',
                owned={}, windows=[], traffic=[], metrics=[], cleanup={})
            self.save()

    def own(self, name, value):
        self.data['owned'][name] = value
        self.save()
        print('OWNED ' + name + '=' + str(value), flush=True)
        return value

    def call(self, label, service_kind, method, **parameters):
        return self.observe(label, service_kind, method, parameters, required=True)

    def wait(self, label, service, method, parameters, predicate, attempts=90, delay=5):
        for i in range(attempts):
            out = self.call(label + '-' + str(i), service, method, **parameters)
            if predicate(out): return out
            time.sleep(delay)
        raise RuntimeError(label + ' timed out')

    def policy(self, name, label, resource=None):
        p = dict(ServiceNamespace='ecs', ScalableDimension='ecs:service:DesiredCount', ResourceId=resource or self.data['owned']['resource'],
            PolicyName=name, PolicyType='TargetTrackingScaling', TargetTrackingScalingPolicyConfiguration=dict(TargetValue=20, PredefinedMetricSpecification=dict(PredefinedMetricType='ALBRequestCountPerTarget')))
        if label is not None: p['TargetTrackingScalingPolicyConfiguration']['PredefinedMetricSpecification']['ResourceLabel'] = label
        out = self.observe('policy-' + name, 'application-autoscaling', 'put_scaling_policy', p)
        if out.get('Alarms'):
            self.call('alarms-' + name, 'cloudwatch', 'describe_alarms', AlarmNames=[a['AlarmName'] for a in out['Alarms']])
        return out

    def window(self, label, paths=(), count=1):
        # Whole minute boundaries avoid attributing traffic to a guessed bucket.
        time.sleep(60 - time.time() % 60 + 1)
        start = now()
        url = 'http://' + self.data['owned']['dns']
        for path in paths:
            for i in range(count):
                at = now()
                try:
                    with urllib.request.urlopen(url + path, timeout=15) as response:
                        status, body = response.status, response.read().decode()
                except urllib.error.HTTPError as error:
                    status, body = error.code, error.read().decode()
                except Exception as error:
                    status, body = 0, repr(error)
                self.data['traffic'].append(dict(window=label, path=path, at=at, status=status, body=body))
        self.data['windows'].append(dict(label=label, start=start, end=now()))
        self.save()
        time.sleep(61 - time.time() % 60)

    def run(self):
        p, o = self.data['prefix'], self.data['owned']
        self.call('placement-vpc', 'ec2', 'describe_vpcs', VpcIds=[VPC])
        subnets = self.call('placement-subnets', 'ec2', 'describe_subnets', SubnetIds=SUBNETS)['Subnets']
        assert all(s['VpcId'] == VPC and s['AvailableIpAddressCount'] >= 12 for s in subnets)
        self.call('placement-routes', 'ec2', 'describe_route_tables', Filters=[dict(Name='vpc-id', Values=[VPC])])
        self.call('placement-acls', 'ec2', 'describe_network_acls', Filters=[dict(Name='vpc-id', Values=[VPC])])
        sg = self.own('sg', self.call('create-group', 'ec2', 'create_security_group', GroupName=p, Description=p, VpcId=VPC)['GroupId'])
        self.call('owned-group-http', 'ec2', 'authorize_security_group_ingress', GroupId=sg, IpPermissions=[dict(IpProtocol='tcp', FromPort=80, ToPort=80, IpRanges=[dict(CidrIp='0.0.0.0/0')]), dict(IpProtocol='tcp', FromPort=8080, ToPort=8082, UserIdGroupPairs=[dict(GroupId=sg)])])
        ami = self.call('resolve-image', 'ssm', 'get_parameter', Name='/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64')['Parameter']['Value']
        instance = self.call('launch-owned-target', 'ec2', 'run_instances', ImageId=ami, InstanceType='t3.micro', MinCount=1, MaxCount=1,
            NetworkInterfaces=[dict(DeviceIndex=0, SubnetId=SUBNETS[0], Groups=[sg], AssociatePublicIpAddress=True)],
            UserData=USER_DATA,
            BlockDeviceMappings=[dict(DeviceName='/dev/xvda', Ebs=dict(VolumeSize=8, VolumeType='gp3', DeleteOnTermination=True))],
            TagSpecifications=[dict(ResourceType='instance', Tags=[dict(Key='Name', Value=p)])])['Instances'][0]
        self.own('instance', instance['InstanceId'])
        self.own('volume_ids', [x['Ebs']['VolumeId'] for x in instance.get('BlockDeviceMappings', [])])
        lb = self.call('create-alb', 'elbv2', 'create_load_balancer', Name=p, Subnets=SUBNETS, SecurityGroups=[sg], Scheme='internet-facing', Type='application', IpAddressType='ipv4')['LoadBalancers'][0]
        self.own('lb', lb['LoadBalancerArn']); self.own('dns', lb['DNSName']); self.own('cost_started', now())
        tg = self.own('tg', self.call('create-target-group', 'elbv2', 'create_target_group', Name=p, Protocol='HTTP', Port=8080, VpcId=VPC, TargetType='instance', HealthCheckIntervalSeconds=5, HealthCheckTimeoutSeconds=2, HealthyThresholdCount=2, UnhealthyThresholdCount=2)['TargetGroups'][0]['TargetGroupArn'])
        empty = self.own('empty_tg', self.call('create-empty-target-group', 'elbv2', 'create_target_group', Name=p+'-empty', Protocol='HTTP', Port=8080, VpcId=VPC, TargetType='instance')['TargetGroups'][0]['TargetGroupArn'])
        listener = self.own('listener', self.call('create-listener', 'elbv2', 'create_listener', LoadBalancerArn=o['lb'], Protocol='HTTP', Port=80, DefaultActions=[dict(Type='forward', TargetGroupArn=tg)])['Listeners'][0]['ListenerArn'])
        for priority, path, action in [(1,'/fixed',dict(Type='fixed-response',FixedResponseConfig=dict(StatusCode='201',ContentType='text/plain',MessageBody='fixed'))), (2,'/redirect',dict(Type='redirect',RedirectConfig=dict(Protocol='HTTP',Port='80',Host='#{host}',Path='/fixed',Query='',StatusCode='HTTP_302'))), (3,'/empty',dict(Type='forward',TargetGroupArn=empty))]:
            self.call('create-rule-'+path, 'elbv2', 'create_rule', ListenerArn=listener, Priority=priority, Conditions=[dict(Field='path-pattern',Values=[path])], Actions=[action])
        self.wait('instance-running','ec2','describe_instances',dict(InstanceIds=[o['instance']]),lambda x:x['Reservations'][0]['Instances'][0]['State']['Name']=='running')
        described = self.call('instance-volumes','ec2','describe_instances',InstanceIds=[o['instance']])['Reservations'][0]['Instances'][0]
        self.own('volume_ids',[x['Ebs']['VolumeId'] for x in described['BlockDeviceMappings']])
        self.wait('alb-active','elbv2','describe_load_balancers',dict(LoadBalancerArns=[o['lb']]),lambda x:x['LoadBalancers'][0]['State']['Code']=='active')
        # Zero-replica service admission exercises native label laziness for an unbound service.
        cluster = self.own('cluster', self.call('create-cluster','ecs','create_cluster',clusterName=p)['cluster']['clusterName'])
        definition = self.own('definition',self.call('register-definition','ecs','register_task_definition',family=p,networkMode='awsvpc',requiresCompatibilities=['FARGATE'],cpu='256',memory='512',containerDefinitions=[dict(name='web',image='public.ecr.aws/docker/library/busybox:1.36',essential=True,portMappings=[dict(containerPort=8080)])])['taskDefinition']['taskDefinitionArn'])
        self.call('create-service','ecs','create_service',cluster=cluster,serviceName=p,taskDefinition=definition,desiredCount=0,launchType='FARGATE',networkConfiguration=dict(awsvpcConfiguration=dict(subnets=[SUBNETS[0]],securityGroups=[sg])))
        resource=self.own('resource','service/'+cluster+'/'+p)
        self.call('register-target','application-autoscaling','register_scalable_target',ServiceNamespace='ecs',ResourceId=resource,ScalableDimension='ecs:service:DesiredCount',MinCapacity=0,MaxCapacity=0)
        label=o['lb'].split(':loadbalancer/')[1]+'/'+tg.split(':')[-1]
        self.own('label',label)
        for name, candidate in [('missing',None),('malformed','bad'),('shape-only','app/missing/0000000000000000/targetgroup/missing/0000000000000000'),('unbound',label),('wrong-id',label[:-1]+'0')]:
            self.policy(name,candidate)
        self.window('zero-target',('/empty',),3)
        self.call('register-two-healthy','elbv2','register_targets',TargetGroupArn=tg,Targets=[dict(Id=o['instance'],Port=8080),dict(Id=o['instance'],Port=8081)])
        self.wait('targets-healthy','elbv2','describe_target_health',dict(TargetGroupArn=tg),lambda x:len(x['TargetHealthDescriptions'])==2 and all(t['TargetHealth']['State']=='healthy' for t in x['TargetHealthDescriptions']))
        self.window('healthy-idle')
        self.window('healthy-traffic',('/', '/error'),12)
        self.window('fixed-and-empty',('/fixed','/empty'),8)
        self.call('register-unhealthy','elbv2','register_targets',TargetGroupArn=tg,Targets=[dict(Id=o['instance'],Port=8082)])
        self.wait('one-unhealthy','elbv2','describe_target_health',dict(TargetGroupArn=tg),lambda x:any(t['TargetHealth']['State']=='unhealthy' for t in x['TargetHealthDescriptions']))
        self.window('two-healthy-one-unhealthy',('/',),12)
        self.call('remove-healthy','elbv2','deregister_targets',TargetGroupArn=tg,Targets=[dict(Id=o['instance'],Port=8080),dict(Id=o['instance'],Port=8081)])
        self.window('failed-forward',('/',),8)
        self.window('unhealthy-idle')
        time.sleep(120)
        self.capture_metrics()

    def capture_metrics(self):
        o=self.data['owned']; start=datetime.datetime.fromisoformat(self.data['captured_at']); end=datetime.datetime.now(datetime.timezone.utc)
        for group in ('tg','empty_tg'):
            dims=[dict(Name='LoadBalancer',Value=o['lb'].split(':loadbalancer/')[1]),dict(Name='TargetGroup',Value=o[group].split(':')[-1])]
            for name in ('RequestCountPerTarget','RequestCount','HealthyHostCount','UnHealthyHostCount','HTTPCode_Target_2XX_Count','TargetConnectionErrorCount'):
                out=self.call('metrics-'+group+'-'+name,'cloudwatch','get_metric_statistics',Namespace='AWS/ApplicationELB',MetricName=name,Dimensions=dims,StartTime=start,EndTime=end,Period=60,Statistics=['Sum','Average','Minimum','Maximum','SampleCount'])
                self.data['metrics'].append(dict(group=group,metric=name,**out)); self.save()
        self.call('list-metrics','cloudwatch','list_metrics',Namespace='AWS/ApplicationELB',Dimensions=[dict(Name='LoadBalancer',Value=o['lb'].split(':loadbalancer/')[1])])

    def cleanup(self):
        o=self.data['owned']; errors=[]
        def attempt(name,service_kind,method,**parameters):
            try:
                out=self.observe('cleanup-'+name,service_kind,method,parameters)
                code=self.data['calls'][-1]['code']; self.data['cleanup'][name]=code
                if code not in ('Success','LoadBalancerNotFound','TargetGroupNotFound','ObjectNotFoundException','InvalidGroup.NotFound','InvalidInstanceID.NotFound','InvalidVolume.NotFound'): errors.append(name+':'+code)
                return out
            except Exception as error: errors.append(name+':'+repr(error)); return {}
        if o.get('resource'): attempt('scaling-target','application-autoscaling','deregister_scalable_target',ServiceNamespace='ecs',ResourceId=o['resource'],ScalableDimension='ecs:service:DesiredCount')
        if o.get('cluster'):
            attempt('service','ecs','delete_service',cluster=o['cluster'],service=self.data['prefix'],force=True)
            attempt('cluster','ecs','delete_cluster',cluster=o['cluster'])
        if o.get('definition'):
            attempt('definition-inactive','ecs','deregister_task_definition',taskDefinition=o['definition'])
            attempt('definition-delete','ecs','delete_task_definitions',taskDefinitions=[o['definition']])
        if o.get('lb'): attempt('load-balancer','elbv2','delete_load_balancer',LoadBalancerArn=o['lb'])
        if o.get('instance'):
            attempt('terminate-instance','ec2','terminate_instances',InstanceIds=[o['instance']])
            self.wait('cleanup-instance-terminated','ec2','describe_instances',dict(InstanceIds=[o['instance']]),lambda x:x['Reservations'][0]['Instances'][0]['State']['Name']=='terminated',attempts=60)
        for key in ('tg','empty_tg'):
            if o.get(key): attempt(key,'elbv2','delete_target_group',TargetGroupArn=o[key])
        if o.get('sg'):
            self.wait('cleanup-eni-absent','ec2','describe_network_interfaces',dict(Filters=[dict(Name='group-id',Values=[o['sg']])]),lambda x:not x['NetworkInterfaces'],attempts=120)
            attempt('security-group','ec2','delete_security_group',GroupId=o['sg'])
            attempt('security-group-absent','ec2','describe_security_groups',GroupIds=[o['sg']])
        if o.get('lb'): attempt('load-balancer-absent','elbv2','describe_load_balancers',LoadBalancerArns=[o['lb']])
        for vol in o.get('volume_ids',[]): attempt('volume-absent-'+vol,'ec2','describe_volumes',VolumeIds=[vol])
        self.data['cleanup'].update(finished_at=now(),errors=errors); self.save()

    def audit(self):
        requests={r['request_id']:r['label'] for r in self.data['calls'] if r.get('request_id') and r['service'] not in ('cloudwatch','cloudtrail')}
        self.data['audit']=collect_history(lambda p:self.clients['cloudtrail'].lookup_events(**p),requests,start_time=self.data['captured_at'],end_time=now(),max_pages=60,rounds=2,wait_seconds=10)
        self.save()

if __name__=='__main__':
    parser=argparse.ArgumentParser(); parser.add_argument('--output',type=Path,required=True); parser.add_argument('--region',default='us-east-1'); parser.add_argument('--cleanup-only',action='store_true'); parser.add_argument('--audit-only',action='store_true')
    parser.add_argument('--account', required=True)
    args=parser.parse_args(); probe=Probe(args)
    if args.audit_only: probe.audit()
    else:
        def interrupted(signum,frame): raise RuntimeError('bounded probe interrupted '+str(signum))
        for sig in (signal.SIGTERM,signal.SIGINT,signal.SIGALRM): signal.signal(sig,interrupted)
        signal.alarm(1800)
        try:
            if not args.cleanup_only: probe.run()
        finally:
            signal.alarm(0); probe.cleanup()
        probe.audit()
