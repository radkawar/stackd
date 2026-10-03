#!/usr/bin/env python3
"""Free exact-owned ECS/ALB policy admission continuation during a metric probe."""
import argparse
import json
from pathlib import Path
from alb_metrics_scaling_probe import Probe

parser=argparse.ArgumentParser(); parser.add_argument('--output',type=Path,required=True); parser.add_argument('--source',type=Path,required=True); parser.add_argument('--region',default='us-east-1'); parser.add_argument('--audit-only',action='store_true'); parser.add_argument('--cleanup-only',action='store_true')
parser.add_argument('--account', required=True)
args=parser.parse_args(); p=Probe(args)
if args.audit_only:
    p.audit()
else:
    source=json.loads(args.source.read_text()); o=source['owned']; prefix=source['prefix']+'-ip'
    if source['account'] != args.account or source['region'] != args.region:
        raise RuntimeError('Source capture ownership mismatch')
    p.data['owned']={'source_lb':o['lb'],'source_service':o['resource'],'policies':[]}; p.data.pop('payload',None)
    p.data['scope']='Free policy calibration on exact-owned zero-replica ECS service; one own IP target group and listener rule, removed in finally'
    try:
        tg=p.own('tg',p.call('create-policy-target-group','elbv2','create_target_group',Name=prefix,Protocol='HTTP',Port=8080,VpcId='vpc-0aeae393af73839cf',TargetType='ip')['TargetGroups'][0]['TargetGroupArn'])
        rule=p.own('rule',p.call('attach-policy-target-group','elbv2','create_rule',ListenerArn=o['listener'],Priority=10,Conditions=[dict(Field='path-pattern',Values=['/policy'])],Actions=[dict(Type='forward',TargetGroupArn=tg)])['Rules'][0]['RuleArn'])
        p.call('bind-service','ecs','update_service',cluster=o['cluster'],service=source['prefix'],loadBalancers=[dict(targetGroupArn=tg,containerName='web',containerPort=8080)])
        label=o['lb'].split(':loadbalancer/')[1]+'/'+tg.split(':')[-1]
        for name,candidate in [('bound',label),('wrong-balancer','app/missing/0000000000000000/'+tg.split(':')[-1]),('wrong-tg-id',label[:-1]+'f'),('net-shape',label.replace('app/','net/',1)),('short-ids','app/a/b/targetgroup/c/d'),('extra-path',label+'/x')]:
            result=p.policy(name,candidate,o['resource'])
            if result.get('PolicyARN'): p.data['owned']['policies'].append(name); p.save()
    finally:
        for name in p.data['owned']['policies']:
            p.observe('cleanup-policy-'+name,'application-autoscaling','delete_scaling_policy',dict(PolicyName=name,ServiceNamespace='ecs',ResourceId=o['resource'],ScalableDimension='ecs:service:DesiredCount'))
        p.observe('cleanup-unbind-service','ecs','update_service',dict(cluster=o['cluster'],service=source['prefix'],loadBalancers=[]))
        if p.data['owned'].get('rule'): p.observe('cleanup-rule','elbv2','delete_rule',dict(RuleArn=p.data['owned']['rule']))
        if p.data['owned'].get('tg'): p.observe('cleanup-target-group','elbv2','delete_target_group',dict(TargetGroupArn=p.data['owned']['tg']))
    p.audit()
