#!/usr/bin/env python3
"""Explicit local CLI/QEMU public IPv4 proof; never contacts native AWS.

Requires an already running stackd endpoint, an immutable raw Ubuntu cloud disk,
and local rootful Docker/QEMU networking. Saves owned resources between phases.
"""
import argparse
import base64
import concurrent.futures
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time
import urllib.request

import boto3
from botocore.config import Config

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('phase', choices=['import', 'launch', 'egress', 'exercise', 'policy', 'ecs', 'restart-check', 'lifecycle', 'cleanup'])
p.add_argument('--endpoint', default='http://127.0.0.1:4577')
p.add_argument('--state', default='/tmp/stackd-eip-763241985012-proof.json')
p.add_argument('--disk', default='/tmp/stackd-ubuntu-24.04-server.raw')
a = p.parse_args()
state_path = Path(a.state)
s = json.loads(state_path.read_text()) if state_path.exists() else {'endpoint': a.endpoint, 'observations': []}
config = Config(retries={'max_attempts': 1}, connect_timeout=5, read_timeout=120, max_pool_connections=16)
session = boto3.Session(aws_access_key_id='test', aws_secret_access_key='test', region_name='us-east-1')
ec2 = session.client('ec2', endpoint_url=a.endpoint, config=config)
ebs = session.client('ebs', endpoint_url=a.endpoint, config=config)
iam = session.client('iam', endpoint_url=a.endpoint, config=config)
ecs = session.client('ecs', endpoint_url=a.endpoint, config=config)
http = urllib.request.build_opener(urllib.request.ProxyHandler({}))

def save():
    state_path.write_text(json.dumps(s, indent=2, default=str)+'\n')

def observe(label, **values):
    row = {'label': label, 'at': time.time(), **values}
    s['observations'].append(row)
    save()
    print(json.dumps(row, default=str), flush=True)

def wait(label, fn, timeout=180):
    deadline = time.monotonic()+timeout
    last = None
    while time.monotonic() < deadline:
        try:
            value = fn()
            if value:
                return value
        except Exception as err:
            last = repr(err)
        time.sleep(1)
    raise RuntimeError(f'{label} timed out: {last}')

def instance(i):
    return ec2.describe_instances(InstanceIds=[i])['Reservations'][0]['Instances'][0]

def public(i):
    return instance(i).get('PublicIpAddress')

def get(ip):
    with http.open(f'http://{ip}:8080/receiver', timeout=2) as r:
        return r.read().decode().strip()

def denied(ip):
    try:
        get(ip)
        return False
    except Exception:
        return True

def ssh(ip, command):
    result = subprocess.run(['ssh', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=3', '-o', 'StrictHostKeyChecking=no', '-o', 'UserKnownHostsFile=/dev/null', '-i', s['key_path'], 'ubuntu@'+ip, command], text=True, capture_output=True, timeout=15)
    if result.returncode:
        raise RuntimeError(f'guest SSH failed ({result.returncode}): {result.stderr}')
    return result.stdout.strip()

def expected_code(label, code, fn):
    from botocore.exceptions import ClientError
    try:
        fn()
    except ClientError as err:
        actual=err.response['Error']['Code']
        if actual != code:
            raise
        observe(label, code=actual)
    else:
        raise AssertionError(label+' unexpectedly succeeded')

SERVICE = '''[Unit]
Description=Stackd public network proof receiver
After=network.target
[Service]
ExecStart=/usr/bin/python3 -m http.server 8080 --directory /var/tmp/public-proof
Restart=always
[Install]
WantedBy=multi-user.target
'''

def user_data(receiver):
    return f'''#cloud-config
write_files:
  - path: /etc/systemd/system/stackd-public-proof.service
    content: |
      {SERVICE.rstrip().replace(chr(10), chr(10)+'      ')}
runcmd:
  - [mkdir, -p, /var/tmp/public-proof]
  - [sh, -c, 'echo {receiver} > /var/tmp/public-proof/receiver']
  - [systemctl, enable, --now, stackd-public-proof.service]
'''

if a.phase == 'import':
    if 'snapshot' not in s:
        s['snapshot'] = ebs.start_snapshot(VolumeSize=4, ClientToken='public-network-firmware-763241985012', Description='Owned local Ubuntu firmware public-network proof')['SnapshotId']; save()
        size = 512*1024
        def upload(item):
            index, data = item
            ebs.put_snapshot_block(SnapshotId=s['snapshot'], BlockIndex=index, BlockData=data, DataLength=len(data), Checksum=base64.b64encode(hashlib.sha256(data).digest()).decode(), ChecksumAlgorithm='SHA256')
        def blocks():
            with open(a.disk, 'rb') as f:
                index = 0
                while data := f.read(size):
                    data = data.ljust(size,b'\0')
                    if any(data):
                        yield index,data
                    index += 1
        count = 0
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            # map's bounded buffer prevents a second in-memory disk copy.
            pending = set()
            for item in blocks():
                pending.add(pool.submit(upload,item)); count += 1
                if len(pending) >= 16:
                    done,pending = concurrent.futures.wait(pending,return_when=concurrent.futures.FIRST_COMPLETED)
                    for result in done: result.result()
            for result in pending: result.result()
        ebs.complete_snapshot(SnapshotId=s['snapshot'], ChangedBlocksCount=count)
        wait('snapshot complete',lambda: ec2.describe_snapshots(SnapshotIds=[s['snapshot']])['Snapshots'][0]['State']=='completed')
        observe('firmware-import', snapshot=s['snapshot'], nonzero_blocks=count, source=a.disk)
    if 'image' not in s:
        s['image'] = ec2.register_image(Name='public-network-ubuntu-763241985012', Architecture='x86_64', VirtualizationType='hvm', RootDeviceName='/dev/sda1', BootMode='legacy-bios', BlockDeviceMappings=[{'DeviceName':'/dev/sda1','Ebs':{'SnapshotId':s['snapshot'],'VolumeSize':4,'VolumeType':'gp3','DeleteOnTermination':True}}])['ImageId']; save()
    observe('image-ready',image=s['image'])

elif a.phase == 'launch':
    s['vpc'] = ec2.create_vpc(CidrBlock='10.234.0.0/24')['Vpc']['VpcId']; save()
    ec2.modify_vpc_attribute(VpcId=s['vpc'],EnableDnsHostnames={'Value':True})
    s['subnet'] = ec2.create_subnet(VpcId=s['vpc'],CidrBlock='10.234.0.0/25')['Subnet']['SubnetId']; save()
    ec2.modify_subnet_attribute(SubnetId=s['subnet'],MapPublicIpOnLaunch={'Value':True})
    s['gateway'] = ec2.create_internet_gateway()['InternetGateway']['InternetGatewayId']; save()
    ec2.attach_internet_gateway(InternetGatewayId=s['gateway'],VpcId=s['vpc'])
    s['route'] = ec2.describe_route_tables(Filters=[{'Name':'vpc-id','Values':[s['vpc']]}])['RouteTables'][0]['RouteTableId']; save()
    ec2.create_route(RouteTableId=s['route'],DestinationCidrBlock='0.0.0.0/0',GatewayId=s['gateway'])
    s['group'] = ec2.create_security_group(VpcId=s['vpc'],GroupName='public-network-proof',Description='Owned real guest SSH HTTP')['GroupId']; save()
    s['permissions'] = [{'IpProtocol':'tcp','FromPort':port,'ToPort':port,'IpRanges':[{'CidrIp':'0.0.0.0/0'}]} for port in (22,8080)]
    ec2.authorize_security_group_ingress(GroupId=s['group'],IpPermissions=s['permissions'])
    key=ec2.create_key_pair(KeyName='public-network-proof-763241985012')
    s['key_name']=key['KeyName']; s['key_path']=str(state_path.with_suffix('.pem')); save()
    fd=os.open(s['key_path'],os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    with os.fdopen(fd,'w') as f: f.write(key['KeyMaterial'])
    s['instances']=[]
    for label,auto in [('guest-A',True),('guest-B',False)]:
        kwargs={'ImageId':s['image'],'InstanceType':'t3.micro','MinCount':1,'MaxCount':1,'KeyName':s['key_name'],'UserData':user_data(label),'MetadataOptions':{'HttpTokens':'required'},'ClientToken':'public-network-'+label+'-763241985012'}
        if auto: kwargs.update(SubnetId=s['subnet'],SecurityGroupIds=[s['group']])
        else: kwargs['NetworkInterfaces']=[{'DeviceIndex':0,'SubnetId':s['subnet'],'Groups':[s['group']],'AssociatePublicIpAddress':False,'DeleteOnTermination':True}]
        i=ec2.run_instances(**kwargs)['Instances'][0]['InstanceId']; s['instances'].append(i); save()
    for i in s['instances']: wait('running '+i,lambda: instance(i)['State']['Name']=='running')
    ip=wait('automatic public address',lambda:public(s['instances'][0]))
    wait('firmware HTTP A',lambda:get(ip)=='guest-A',timeout=300)
    boot=wait('firmware SSH A',lambda:ssh(ip,'cat /proc/sys/kernel/random/boot_id'))
    assert not public(s['instances'][1])
    s['automatic_initial']=ip;s['boot_initial']=boot;save()
    observe('automatic-subnet-public-reachability',ip=ip,receiver=get(ip),boot_id=boot,ssh=ssh(ip,'uname -sr'),private_only_public=public(s['instances'][1]))

elif a.phase == 'egress':
    ip=public(s['instances'][0])
    private=instance(s['instances'][1])['PrivateIpAddress']
    wait('private-only SSH control',lambda:ssh(private,'cat /proc/sys/kernel/random/boot_id'))
    blocked=ssh(private,"curl --noproxy '*' --connect-timeout 3 --max-time 5 --silent https://1.1.1.1/cdn-cgi/trace >/dev/null; echo $?")
    assert blocked != '0',blocked
    trace=ssh(ip,"curl --noproxy '*' --fail --connect-timeout 3 --max-time 8 --silent https://1.1.1.1/cdn-cgi/trace")
    assert 'ip=' in trace,trace
    observe('public-egress-prerequisite',private_guest_curl_exit=blocked,assigned_guest_external_trace=trace)

elif a.phase == 'exercise':
    first,second=s['instances']
    address=ec2.allocate_address(Domain='vpc',TagSpecifications=[{'ResourceType':'elastic-ip','Tags':[{'Key':'suite','Value':'public-network-proof'}]}])
    s['allocation']=address['AllocationId'];s['elastic']=address['PublicIp'];save()
    s['association']=ec2.associate_address(AllocationId=s['allocation'],InstanceId=first)['AssociationId'];save()
    wait('EIP receiver A',lambda:get(s['elastic'])=='guest-A')
    wait('old ephemeral retired',lambda:denied(s['automatic_initial']))
    observe('elastic-inbound',address=s['elastic'],receiver=get(s['elastic']),ssh_boot=ssh(s['elastic'],'cat /proc/sys/kernel/random/boot_id'))
    expected_code('release-associated-denied','InvalidIPAddress.InUse',lambda:ec2.release_address(AllocationId=s['allocation']))
    expected_code('reassociation-false-denied','Resource.AlreadyAssociated',lambda:ec2.associate_address(AllocationId=s['allocation'],InstanceId=second,AllowReassociation=False))
    ec2.revoke_security_group_ingress(GroupId=s['group'],IpPermissions=s['permissions'])
    wait('SG denial',lambda:denied(s['elastic']))
    observe('security-group-denial',address=s['elastic'])
    ec2.authorize_security_group_ingress(GroupId=s['group'],IpPermissions=s['permissions'])
    wait('SG restored',lambda:get(s['elastic'])=='guest-A')

elif a.phase == 'policy':
    first,second=s['instances']
    acl_record=ec2.describe_network_acls(Filters=[{'Name':'vpc-id','Values':[s['vpc']]}])['NetworkAcls'][0]
    acl=acl_record['NetworkAclId']
    if not any(e['RuleNumber']==10 and not e['Egress'] for e in acl_record['Entries']):
        ec2.create_network_acl_entry(NetworkAclId=acl,RuleNumber=10,Protocol='6',RuleAction='deny',Egress=False,CidrBlock='0.0.0.0/0',PortRange={'From':8080,'To':8080})
    wait('NACL denial',lambda:denied(s['elastic']))
    observe('host-local-ingress-network-acl-denial',address=s['elastic'])
    ec2.delete_network_acl_entry(NetworkAclId=acl,RuleNumber=10,Egress=False)
    wait('NACL restored',lambda:get(s['elastic'])=='guest-A')
    ec2.create_network_acl_entry(NetworkAclId=acl,RuleNumber=10,Protocol='6',RuleAction='deny',Egress=True,CidrBlock='0.0.0.0/0',PortRange={'From':1024,'To':65535})
    wait('return NACL denial',lambda:denied(s['elastic']))
    observe('host-local-return-network-acl-denial',address=s['elastic'])
    ec2.delete_network_acl_entry(NetworkAclId=acl,RuleNumber=10,Egress=True)
    wait('return NACL restored',lambda:get(s['elastic'])=='guest-A')
    ec2.delete_route(RouteTableId=s['route'],DestinationCidrBlock='0.0.0.0/0')
    wait('IGW route denial',lambda:denied(s['elastic']))
    observe('internet-route-denial',address=s['elastic'])
    ec2.create_route(RouteTableId=s['route'],DestinationCidrBlock='0.0.0.0/0',GatewayId=s['gateway'])
    wait('IGW restored',lambda:get(s['elastic'])=='guest-A')
    s['association']=ec2.associate_address(AllocationId=s['allocation'],InstanceId=second)['AssociationId'];save()
    wait('EIP receiver B',lambda:get(s['elastic'])=='guest-B',timeout=300)
    s['boot_before_restart']=ssh(s['elastic'],'cat /proc/sys/kernel/random/boot_id');save()
    assert s['boot_before_restart'] != s['boot_initial']
    observe('reassociation-receiving-guest-changed',address=s['elastic'],receiver=get(s['elastic']),boot_id=s['boot_before_restart'],restored_ephemeral=public(first))
    token=ssh(s['elastic'],"curl --fail --silent -X PUT -H 'X-aws-ec2-metadata-token-ttl-seconds: 60' http://169.254.169.254/latest/api/token")
    metadata=ssh(s['elastic'],f"curl --fail --silent -H 'X-aws-ec2-metadata-token: {token}' http://169.254.169.254/latest/meta-data/public-ipv4")
    assert metadata==s['elastic']
    observe('IMDS-public-owner',public_ipv4=metadata)
    current=instance(second)
    hostname=current['PublicDnsName']
    resolved=ssh(s['elastic'],f'getent ahostsv4 {hostname}').splitlines()[0].split()[0]
    assert resolved==current['PrivateIpAddress'],(hostname,resolved,current)
    metadata_hostname=ssh(s['elastic'],f"curl --fail --silent -H 'X-aws-ec2-metadata-token: {token}' http://169.254.169.254/latest/meta-data/public-hostname")
    assert metadata_hostname==hostname
    eni=current['NetworkInterfaces'][0]
    mapped=ssh(s['elastic'],f"curl --fail --silent -H 'X-aws-ec2-metadata-token: {token}' http://169.254.169.254/latest/meta-data/network/interfaces/macs/{eni['MacAddress']}/ipv4-associations/{s['elastic']}")
    assert mapped==current['PrivateIpAddress']
    observe('guest-DNS-and-IMDS-association',public_hostname=hostname,guest_resolution=resolved,metadata_private_association=mapped)
    uname=ssh(s['elastic'],'uname -sr')
    observe('firmware-guest-identity',uname=uname)
    # IAM applies to address API authority, not customer TCP packets.
    name='PublicNetworkOperator';iam.create_user(UserName=name);s['user']=name;save()
    key=iam.create_access_key(UserName=name)['AccessKey'];s['access_key']=key['AccessKeyId'];save()
    policy={'Version':'2012-10-17','Statement':[{'Effect':'Allow','Action':'ec2:*','Resource':'*'}]}
    iam.put_user_policy(UserName=name,PolicyName='public-network',PolicyDocument=json.dumps(policy))
    delegated=session.client('ec2',endpoint_url=a.endpoint,config=config,aws_access_key_id=key['AccessKeyId'],aws_secret_access_key=key['SecretAccessKey'])
    delegated.describe_addresses(AllocationIds=[s['allocation']])
    policy['Statement'].append({'Effect':'Deny','Action':'ec2:AssociateAddress','Resource':'*'})
    iam.put_user_policy(UserName=name,PolicyName='public-network',PolicyDocument=json.dumps(policy))
    expected_code('current-IAM-denial','UnauthorizedOperation',lambda:delegated.associate_address(AllocationId=s['allocation'],InstanceId=first))
    assert get(s['elastic'])=='guest-B'
    eni_resource=f"arn:aws:ec2:us-east-1:763241985012:network-interface/{eni['NetworkInterfaceId']}"
    policy['Statement'].append({'Effect':'Deny','Action':'ec2:DisassociateAddress','Resource':eni_resource})
    iam.put_user_policy(UserName=name,PolicyName='public-network',PolicyDocument=json.dumps(policy))
    for dry in [True,False]:
        expected_code('current-interface-IAM-denial','UnauthorizedOperation',lambda:delegated.disassociate_address(AssociationId=s['association'],DryRun=dry))
    assert get(s['elastic'])=='guest-B'

elif a.phase == 'restart-check':
    ip=s['elastic'];boot=wait('restart surviving guest',lambda:ssh(ip,'cat /proc/sys/kernel/random/boot_id'))
    assert boot==s['boot_before_restart']
    assert get(ip)=='guest-B'
    observe('sqlite-controller-reopen-same-guest',public_ip=ip,boot_id=boot,receiver=get(ip))
    if s.get('task_public'):
        assert get(s['task_public'])=='ecs-task'
        observe('sqlite-controller-reopen-ECS',public_ip=s['task_public'],receiver=get(s['task_public']))

elif a.phase == 'lifecycle':
    first,second=s['instances']
    before=public(first)
    ec2.stop_instances(InstanceIds=[first,second])
    for i in (first,second): wait('stopped '+i,lambda:instance(i)['State']['Name']=='stopped')
    assert not public(first);assert public(second)==s['elastic'];assert denied(s['elastic'])
    observe('stopped-address-lifecycle',ephemeral_released=before,elastic_retained=public(second),elastic_reachable=False)
    ec2.start_instances(InstanceIds=[first,second])
    for i in (first,second): wait('started '+i,lambda:instance(i)['State']['Name']=='running')
    wait('restarted B HTTP',lambda:get(s['elastic'])=='guest-B',timeout=300)
    after=public(first);assert after and after != before
    boot=ssh(s['elastic'],'cat /proc/sys/kernel/random/boot_id');assert boot != s['boot_before_restart']
    observe('start-address-lifecycle',new_ephemeral=after,old_ephemeral=before,elastic=s['elastic'],new_boot=boot)
    ec2.disassociate_address(AssociationId=s['association'])
    wait('EIP disassociated native cleanup',lambda:denied(s['elastic']))
    assert not public(second)
    ec2.release_address(AllocationId=s['allocation'])
    expected_code('released-address-absent','InvalidAllocationID.NotFound',lambda:ec2.describe_addresses(AllocationIds=[s['allocation']]))
    observe('elastic-release-no-stale-access',public_ip=s['elastic'],private_only_instance_public=public(second))
    s['released']=True;save()
    address=ec2.allocate_address(Domain='vpc')
    s['allocation']=address['AllocationId'];s['elastic']=address['PublicIp'];s['released']=False;save()
    s['association']=ec2.associate_address(AllocationId=s['allocation'],InstanceId=second)['AssociationId'];save()
    wait('terminal EIP attached',lambda:get(s['elastic'])=='guest-B')
    ec2.terminate_instances(InstanceIds=[second])
    wait('terminal EIP guest terminated',lambda:instance(second)['State']['Name']=='terminated')
    retained=ec2.describe_addresses(AllocationIds=[s['allocation']])['Addresses'][0]
    assert 'AssociationId' not in retained and 'NetworkInterfaceId' not in retained,retained
    wait('terminal EIP native cleanup',lambda:denied(s['elastic']))
    observe('termination-disassociates-without-release',allocation=s['allocation'],public_ip=s['elastic'],retained=retained)
    ec2.release_address(AllocationId=s['allocation'])
    s['released']=True;save()

elif a.phase == 'ecs':
    s['cluster']=ecs.create_cluster(clusterName='public-network-proof')['cluster']['clusterArn'];save()
    s['task_definition']=ecs.register_task_definition(family='public-network-proof',networkMode='awsvpc',requiresCompatibilities=['FARGATE'],cpu='256',memory='512',containerDefinitions=[{'name':'receiver','image':'busybox:1.37.0','essential':True,'entryPoint':['sh','-c'],'command':['mkdir -p /www; echo ecs-task > /www/receiver; exec httpd -f -p 8080 -h /www'],'portMappings':[{'containerPort':8080,'protocol':'tcp'}]}])['taskDefinition']['taskDefinitionArn'];save()
    result=ecs.run_task(cluster=s['cluster'],taskDefinition=s['task_definition'],launchType='FARGATE',networkConfiguration={'awsvpcConfiguration':{'subnets':[s['subnet']],'securityGroups':[s['group']],'assignPublicIp':'ENABLED'}})
    assert not result.get('failures'),result
    s['task']=result['tasks'][0]['taskArn'];save()
    def running_task():
        task=ecs.describe_tasks(cluster=s['cluster'],tasks=[s['task']])['tasks'][0]
        if task['lastStatus']=='STOPPED':raise RuntimeError(task)
        return task if task['lastStatus']=='RUNNING' else None
    task=wait('real ECS task running',running_task)
    eni=next(d['value'] for attachment in task['attachments'] for d in attachment['details'] if d['name']=='networkInterfaceId')
    ip=ec2.describe_network_interfaces(NetworkInterfaceIds=[eni])['NetworkInterfaces'][0]['Association']['PublicIp']
    wait('real ECS public HTTP',lambda:get(ip)=='ecs-task')
    s['task_public']=ip;s['task_eni']=eni;save()
    observe('ecs-assigned-public-ip-consumer',task=s['task'],eni=eni,public_ipv4=ip,receiver=get(ip))

elif a.phase == 'cleanup':
    from botocore.exceptions import ClientError
    if s.get('task'):
        ecs.stop_task(cluster=s['cluster'],task=s['task'],reason='Owned public network smoke cleanup')
        wait('ECS task stopped',lambda:ecs.describe_tasks(cluster=s['cluster'],tasks=[s['task']])['tasks'][0]['lastStatus']=='STOPPED')
        wait('ECS public mapping removed',lambda:denied(s['task_public']))
        ecs.deregister_task_definition(taskDefinition=s['task_definition'])
        ecs.delete_task_definitions(taskDefinitions=[s['task_definition']])
        ecs.delete_cluster(cluster=s['cluster'])
    for i in s.get('instances',[]):
        ec2.terminate_instances(InstanceIds=[i])
    for i in s.get('instances',[]):wait('terminated '+i,lambda:instance(i)['State']['Name']=='terminated')
    if s.get('allocation') and not s.get('released'):
        addresses=ec2.describe_addresses(AllocationIds=[s['allocation']])['Addresses']
        if addresses[0].get('AssociationId'):ec2.disassociate_address(AssociationId=addresses[0]['AssociationId'])
        ec2.release_address(AllocationId=s['allocation']);s['released']=True;save()
    if s.get('user'):
        iam.delete_access_key(UserName=s['user'],AccessKeyId=s['access_key'])
        iam.delete_user_policy(UserName=s['user'],PolicyName='public-network')
        iam.delete_user(UserName=s['user'])
    if s.get('image'):ec2.deregister_image(ImageId=s['image'])
    if s.get('snapshot'):ec2.delete_snapshot(SnapshotId=s['snapshot'])
    if s.get('key_name'):ec2.delete_key_pair(KeyName=s['key_name'])
    if s.get('group'):ec2.delete_security_group(GroupId=s['group'])
    if s.get('gateway'):
        ec2.detach_internet_gateway(InternetGatewayId=s['gateway'],VpcId=s['vpc'])
        ec2.delete_internet_gateway(InternetGatewayId=s['gateway'])
    if s.get('subnet'):ec2.delete_subnet(SubnetId=s['subnet'])
    if s.get('vpc'):ec2.delete_vpc(VpcId=s['vpc'])
    assert ec2.describe_addresses()['Addresses']==[]
    assert ec2.describe_network_interfaces()['NetworkInterfaces']==[]
    observe('owned-control-cleanup',instances={i:instance(i)['State']['Name'] for i in s.get('instances',[])},addresses=[],interfaces=[])
