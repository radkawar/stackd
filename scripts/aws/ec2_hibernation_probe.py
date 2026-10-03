#!/usr/bin/env python3
"""Bounded exact-owned EC2 hibernation admission and guest continuity capture.

One t3.nano at a time, official AL2023, encrypted delete-on-termination gp3
root, isolated private VPC. No public networking or IAM/default changes.
"""
import argparse
import copy
import json
from pathlib import Path
import re
import signal
import time
import uuid

from cloudtrail_events import collect_history
from ec2_instances_probe import InstanceCapture, interrupt
from ebs_encryption_probe import now, safe

GUEST = '''#!/bin/bash
set -eu
cat >/usr/local/bin/hibernate-observe.py <<'PY'
import json,os,pathlib,time,uuid
nonce=uuid.uuid4().hex
boot=pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip()
for counter in range(240):
    with open('/dev/console','w') as out:
        out.write('STACKD_HIBERNATE '+json.dumps({'boot_id':boot,'nonce':nonce,'pid':os.getpid(),'counter':counter,'sampled_at':time.time()})+'\\n')
    time.sleep(5)
PY
cat >/etc/systemd/system/hibernate-observe.service <<'UNIT'
[Unit]
After=network.target
[Service]
ExecStart=/usr/bin/python3 /usr/local/bin/hibernate-observe.py
[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
systemctl enable --now hibernate-observe.service
'''


class HibernationCapture(InstanceCapture):
    def __init__(self, args):
        super().__init__(args)
        if not args.cleanup_only and not args.audit_only:
            self.data.update(prefix='stackd-ec2-hibernate-'+uuid.uuid4().hex[:12],
                scope=__doc__, guest_program=GUEST,
                bounds={'max_simultaneous_instances':1,'experiment_seconds':args.live_seconds,'instance_type':'t3.nano','public_network':False},
                documentation=['https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/'+page+'.html' for page in
                    ('hibernating-prerequisites','hibernating-instances','hibernating-resuming','Hibernate')],
                observations={})
            self.save()

    def guest(self, iid, label, previous=None, changed=False, observed_after=0):
        end=time.monotonic()+180
        attempt=0
        while time.monotonic()<end:
            result=self.ec2(label+'-'+str(attempt),'get_console_output',{'InstanceId':iid,'Latest':True})
            text=re.sub(r'\[\d{4}-\d{2}-\d{2}T[^\]]+\]','',result.get('Output',''))
            rows=[]
            for match in re.finditer(r'STACKD_HIBERNATE (\{[^\r\n]+\})',text):
                try: rows.append(json.loads(match[1]))
                except json.JSONDecodeError: pass
            for row in reversed(rows):
                if row.get('sampled_at',0)<observed_after:
                    continue
                if previous is None or (changed and row['boot_id']!=previous['boot_id']) or (not changed and row['boot_id']==previous['boot_id'] and row['counter']>previous['counter']):
                    self.data['observations'][label]=row
                    self.save()
                    return row
            time.sleep(5)
            attempt+=1
        raise TimeoutError(label+': no matching real guest console observation')

    def run(self):
        self.deadline=time.monotonic()+self.args.live_seconds
        signal.alarm(self.args.live_seconds)
        p=self.data['prefix']
        image_id=self.observe('official-image-parameter','ssm','get_parameter',{'Name':'/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64'},required=True)['Parameter']['Value']
        image=self.ec2('official-image','describe_images',{'ImageIds':[image_id],'Owners':['amazon']},required=True)['Images'][0]
        typ=self.ec2('native-type-hibernation','describe_instance_types',{'InstanceTypes':['t3.nano']},required=True)['InstanceTypes'][0]
        if not typ['HibernationSupported'] or image['RootDeviceType']!='ebs' or image['VirtualizationType']!='hvm' or image['Architecture']!='x86_64' or image.get('Platform')=='windows':
            raise RuntimeError('Native hibernation prerequisites not met')
        root=next(m['Ebs'] for m in image['BlockDeviceMappings'] if m['DeviceName']==image['RootDeviceName'])
        if root['VolumeSize']>8: raise RuntimeError('Official root exceeds cost bound')
        self.data['source_image']=image
        self.data['instance_type']=typ
        zones=self.ec2('zones','describe_availability_zones',{'Filters':[{'Name':'zone-type','Values':['availability-zone']}]},required=True)
        zone=next(z['ZoneName'] for z in zones['AvailabilityZones'] if z['State']=='available')
        owned=self.data['owned']
        owned['vpc']=self.ec2('owned-vpc','create_vpc',{'CidrBlock':'10.233.0.0/24','TagSpecifications':self.tags('vpc')},required=True)['Vpc']['VpcId'];self.save()
        owned['subnet']=self.ec2('owned-subnet','create_subnet',{'VpcId':owned['vpc'],'CidrBlock':'10.233.0.0/28','AvailabilityZone':zone,'TagSpecifications':self.tags('subnet')},required=True)['Subnet']['SubnetId'];self.save()
        owned['group']=self.ec2('owned-group','create_security_group',{'VpcId':owned['vpc'],'GroupName':p,'Description':p,'TagSpecifications':self.tags('security-group')},required=True)['GroupId'];self.save()
        request={'ImageId':image_id,'InstanceType':'t3.nano','MinCount':1,'MaxCount':1,'ClientToken':p+'-unconfigured',
            'SubnetId':owned['subnet'],'SecurityGroupIds':[owned['group']],
            'BlockDeviceMappings':[{'DeviceName':image['RootDeviceName'],'Ebs':{'VolumeSize':8,'VolumeType':'gp3','Encrypted':True,'DeleteOnTermination':True}}],
            'TagSpecifications':self.tags('instance','volume'),'UserData':GUEST}
        invalid=copy.deepcopy(request);invalid.update(ClientToken=p+'-unencrypted',HibernationOptions={'Configured':True})
        invalid['BlockDeviceMappings'][0]['Ebs']['Encrypted']=False
        unexpected=self.ec2('hibernate-unencrypted-root','run_instances',invalid)
        if unexpected.get('Instances'):
            iid=unexpected['Instances'][0]['InstanceId']
            self.ec2('terminate-unexpected-launch','terminate_instances',{'InstanceIds':[iid]},required=True)
            self.state(iid,'terminated','unexpected-terminal')
        first=self.ec2('launch-unconfigured','run_instances',request,required=True)['Instances'][0]['InstanceId']
        self.state(first,'running','unconfigured-running')
        self.ec2('hibernate-unconfigured','stop_instances',{'InstanceIds':[first],'Hibernate':True})
        self.ec2('terminate-unconfigured','terminate_instances',{'InstanceIds':[first]},required=True)
        self.state(first,'terminated','unconfigured-terminal')
        request.update(ClientToken=p+'-configured',HibernationOptions={'Configured':True})
        iid=self.ec2('launch-configured','run_instances',request,required=True)['Instances'][0]['InstanceId']
        self.state(iid,'running','configured-running')
        before=self.guest(iid,'guest-before')
        self.ec2('hibernate-force-dryrun','stop_instances',{'InstanceIds':[iid],'Hibernate':True,'Force':True,'DryRun':True})
        self.ec2('hibernate-skip-dryrun','stop_instances',{'InstanceIds':[iid],'Hibernate':True,'SkipOsShutdown':True,'DryRun':True})
        for attempt in range(24):
            self.ec2('hibernate-configured-'+str(attempt),'stop_instances',{'InstanceIds':[iid],'Hibernate':True})
            row=self.data['calls'][-1]
            if row['code']=='Success':break
            if row['code']!='UnsupportedOperation' or 'not ready to hibernate yet' not in row.get('error',{}).get('Message',''):
                raise RuntimeError('hibernate-configured: '+row['code'])
            time.sleep(15)
        else:raise TimeoutError('Native instance did not become hibernation-ready')
        self.state(iid,'stopped','hibernated-terminal')
        self.ec2('modify-hibernated-type','modify_instance_attribute',{'InstanceId':iid,'InstanceType':{'Value':'t3.micro'}})
        if self.data['calls'][-1]['code']=='Success':
            self.ec2('restore-hibernated-type','modify_instance_attribute',{'InstanceId':iid,'InstanceType':{'Value':'t3.nano'}},required=True)
        self.ec2('ordinary-stop-hibernated','stop_instances',{'InstanceIds':[iid]},required=True)
        resumed_after=time.time()
        self.ec2('resume-hibernated','start_instances',{'InstanceIds':[iid]},required=True)
        self.state(iid,'running','resumed-running')
        resumed=self.guest(iid,'guest-resumed',before,observed_after=resumed_after)
        self.data['observations']['memory_continuity']=resumed['nonce']==before['nonce'] and resumed['pid']==before['pid']
        self.ec2('normal-stop-after-resume','stop_instances',{'InstanceIds':[iid]},required=True)
        self.state(iid,'stopped','normally-stopped')
        self.ec2('modify-normally-stopped-type','modify_instance_attribute',{'InstanceId':iid,'InstanceType':{'Value':'t3.micro'}})
        if self.data['calls'][-1]['code']=='Success':
            self.ec2('restore-normally-stopped-type','modify_instance_attribute',{'InstanceId':iid,'InstanceType':{'Value':'t3.nano'}},required=True)
        self.ec2('cold-start-after-normal-stop','start_instances',{'InstanceIds':[iid]},required=True)
        self.state(iid,'running','cold-running')
        self.guest(iid,'guest-cold',resumed,changed=True)
        self.data['capture_complete_at']=now();self.save()

    def audit(self):
        if not self.data['cleanup'].get('complete'): raise RuntimeError('Cleanup must complete before audit')
        ids={r['request_id']:r['label'] for r in self.data['calls'] if r.get('request_id') and r['service']=='ec2'}
        self.data['cloudtrail']=safe(collect_history(lambda p:self.clients['cloudtrail'].lookup_events(**p),ids,
            start_time=self.data['captured_at'],event_sources=('ec2.amazonaws.com',),max_pages=20,rounds=2,wait_seconds=30,previous=self.data.get('cloudtrail')))
        self.save()


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--account', required=True)
    parser.add_argument('--region',choices=['us-east-1'],default='us-east-1')
    parser.add_argument('--output',type=Path,default=Path('.stackd/probes/ec2/hibernation.json'))
    parser.add_argument('--live-seconds',type=int,default=1200,choices=range(300,1201))
    modes=parser.add_mutually_exclusive_group();modes.add_argument('--cleanup-only',action='store_true');modes.add_argument('--audit-only',action='store_true')
    args=parser.parse_args();capture=HibernationCapture(args)
    if args.audit_only: capture.audit();return
    for sig in (signal.SIGINT,signal.SIGTERM,signal.SIGALRM):signal.signal(sig,interrupt)
    try:
        if not args.cleanup_only:capture.run()
    except Exception as error:
        capture.data['failure']={'type':type(error).__name__,'message':str(error),'at':now()};capture.save();raise
    finally:capture.cleanup()


if __name__=='__main__':main()
