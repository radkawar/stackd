#!/usr/bin/env python3
"""Exercise actual warm-pool guests, memory continuity, ALB and SQLite reopen.

The HTTP process keeps its nonce and counter only in RAM. A separate disk UUID
survives ordinary cold starts. Stopped, Running and Hibernated pools share the
same lifecycle workflow; hibernation must not pass by starting a new process.
"""
import argparse
import base64
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path

from autoscaling_guest_smoke import Smoke as GroupSmoke


USER_DATA = r'''#!/bin/bash
set -eu
exec > >(tee /dev/console) 2>&1
mkdir -p /opt/warm-http
token=$(curl -fsS -X PUT -H 'X-aws-ec2-metadata-token-ttl-seconds: 300' http://169.254.169.254/latest/api/token)
curl -fsS -H "X-aws-ec2-metadata-token: $token" http://169.254.169.254/latest/meta-data/instance-id >/opt/warm-http/instance
cat >/opt/warm-http/server.py <<'PY'
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import os
from pathlib import Path
import uuid

root = Path('/opt/warm-http')
disk = root / 'disk-id'
if not disk.exists():
    disk.write_text(str(uuid.uuid4()))
state = {'instance': (root / 'instance').read_text(), 'disk': disk.read_text(),
         'boot': Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
         'nonce': str(uuid.uuid4()), 'pid': os.getpid(), 'counter': 0}

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/increment':
            state['counter'] += 1
        body = json.dumps(state).encode()
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

HTTPServer(('0.0.0.0', 8080), Handler).serve_forever()
PY
cat >/etc/systemd/system/warm-http.service <<'UNIT'
[Unit]
After=network.target
[Service]
ExecStart=/usr/bin/python3 -u /opt/warm-http/server.py
Restart=on-failure
[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
systemctl enable --now warm-http.service
'''


class Smoke(GroupSmoke):
    def pool(self):
        result = self.client('autoscaling').describe_warm_pool(AutoScalingGroupName=self.prefix)
        for member in result.get('Instances', []):
            iid = member['InstanceId']
            if iid not in self.owned['instances']:
                self.owned['instances'].append(iid)
            self.instance(iid)
        return result

    def warm(self, iid, state):
        result = self.wait('warm member ' + state, self.pool,
                           lambda row: len(row.get('Instances', [])) == 1
                           and row['Instances'][0]['InstanceId'] == iid
                           and row['Instances'][0]['LifecycleState'] == 'Warmed:' + state, 300)
        group = self.group()
        assert group['DesiredCapacity'] == 0 and not group['Instances'], group
        actual = self.instance(iid)
        assert actual['State']['Name'] == ('running' if state == 'Running' else 'stopped'), actual
        return result

    def hook(self, transition, origin, destination, iid=None):
        action = self.action('autoscaling:EC2_INSTANCE_' + transition, iid)
        assert (action['Origin'], action['Destination']) == (origin, destination), action
        return action

    def after_load_balancer(self, lb):
        o = self.owned
        self.prepare_targets(lb, drain_seconds=5)
        self.prepare_events()
        o['template'] = self.call('warm-template', 'ec2', 'create_launch_template', LaunchTemplateName=self.prefix,
            LaunchTemplateData={'ImageId': o['image'], 'InstanceType': 't3.micro',
                'UserData': base64.b64encode(USER_DATA.encode()).decode(),
                'MetadataOptions': {'HttpTokens': 'required', 'InstanceMetadataTags': 'enabled'},
                'Monitoring': {'Enabled': True},
                'NetworkInterfaces': [{'DeviceIndex': 0, 'Groups': [o['sg']], 'DeleteOnTermination': True,
                                       'AssociatePublicIpAddress': False}],
                'BlockDeviceMappings': [{'DeviceName': '/dev/sda1', 'Ebs': {'Encrypted': True, 'VolumeSize': 8,
                                                                         'VolumeType': 'gp3', 'DeleteOnTermination': True}}]
            })['LaunchTemplate']['LaunchTemplateId']
        self.asg('empty-warm-group', 'create_auto_scaling_group', AutoScalingGroupName=self.prefix,
                 LaunchTemplate={'LaunchTemplateId': o['template'], 'Version': '1'},
                 MinSize=0, MaxSize=1, DesiredCapacity=0, VPCZoneIdentifier=o['subnet'],
                 TargetGroupARNs=[o['tg']], HealthCheckGracePeriod=0, DefaultInstanceWarmup=0,
                 LifecycleHookSpecificationList=[
                     {'LifecycleHookName': 'launch', 'LifecycleTransition': 'autoscaling:EC2_INSTANCE_LAUNCHING',
                      'HeartbeatTimeout': 600, 'DefaultResult': 'ABANDON'},
                     {'LifecycleHookName': 'terminate', 'LifecycleTransition': 'autoscaling:EC2_INSTANCE_TERMINATING',
                      'HeartbeatTimeout': 600, 'DefaultResult': 'CONTINUE'}])
        o['group'] = self.prefix
        self.save()
        if self.args.upgrade_from_binary:
            before = self.group()
            self.stop()
            self.args.binary = self.target_binary
            self.start()
            after = self.group()
            for key in ('AutoScalingGroupARN', 'CreatedTime', 'LaunchTemplate', 'VPCZoneIdentifier',
                        'MinSize', 'MaxSize', 'DesiredCapacity', 'TargetGroupARNs'):
                assert after[key] == before[key], (key, before[key], after[key])
            assert not after.get('WarmPoolConfiguration'), after
            self.data['observations']['schema_upgrade'] = {
                'from_binary': str(self.args.upgrade_from_binary), 'to_binary': str(self.target_binary),
                'before': before, 'after': after, 'retained_image': o['image'], 'retained_alb': o['lb']}
            self.save()
        self.asg('warm-capacity-metrics', 'enable_metrics_collection', AutoScalingGroupName=self.prefix,
                 Granularity='1Minute', Metrics=['GroupInServiceInstances', 'GroupTotalInstances',
                 'WarmPoolDesiredCapacity', 'WarmPoolWarmedCapacity', 'GroupAndWarmPoolTotalCapacity'])
        for state in self.args.pool_state:
            if state == 'Hibernated':
                version = self.call('hibernation-template-version', 'ec2', 'create_launch_template_version',
                                    LaunchTemplateId=o['template'], SourceVersion='1',
                                    LaunchTemplateData={'HibernationOptions': {'Configured': True}})['LaunchTemplateVersion']['VersionNumber']
            else:
                version = 1
            self.asg('select-' + state, 'update_auto_scaling_group', AutoScalingGroupName=self.prefix,
                     LaunchTemplate={'LaunchTemplateId': o['template'], 'Version': str(version)})
            self.cycle(state)

    def cycle(self, state):
        o = self.owned
        self.asg('create-' + state + '-pool', 'put_warm_pool', AutoScalingGroupName=self.prefix,
                 PoolState=state, MinSize=0, MaxGroupPreparedCapacity=1,
                 InstanceReusePolicy={'ReuseOnScaleIn': True})
        launch = self.hook('LAUNCHING', 'EC2', 'WarmPool')
        iid = launch['EC2InstanceId']
        self.pool()
        original = self.instance(iid)
        address = original['PrivateIpAddress'] + ':8080'
        before = self.wait('initial warm guest HTTP', lambda: self.http(address),
                           lambda row: row and row['instance'] == iid, 300, 2)
        assert not self.group()['Instances'], self.group()
        seeded = self.http(address + '/increment')
        assert seeded['nonce'] == before['nonce'] and seeded['counter'] == before['counter'] + 1, seeded
        self.complete(launch)
        waiting = self.warm(iid, state)
        if state == 'Running':
            self.gauges(iid)
        if state != 'Running':
            assert self.http(address) is None, 'stopped warm guest still serving'
        self.stop()
        self.start()
        reopened = self.warm(iid, state)
        assert self.instance(iid)['BlockDeviceMappings'] == original['BlockDeviceMappings']
        self.asg('activate-' + state, 'set_desired_capacity', AutoScalingGroupName=self.prefix, DesiredCapacity=1)
        activation = self.hook('LAUNCHING', 'WarmPool', 'AutoScalingGroup', iid)
        active = self.wait('activated warm guest HTTP', lambda: self.http(address),
                           lambda row: row and row['instance'] == iid, 300, 2)
        assert active['disk'] == seeded['disk'], (seeded, active)
        if state == 'Stopped':
            assert active['boot'] != seeded['boot'] and active['nonce'] != seeded['nonce'], (seeded, active)
            assert active['counter'] == 0, active
        else:
            assert active == seeded, (seeded, active)
        self.complete(activation)
        self.wait('warm activation in service', self.group,
                  lambda group: len(group['Instances']) == 1 and group['Instances'][0]['InstanceId'] == iid
                  and group['Instances'][0]['LifecycleState'] == 'InService', 180)
        self.wait('warm guest ALB packet', lambda: self.http(o['dns']), lambda row: row == active, 180)
        self.asg('reuse-' + state, 'set_desired_capacity', AutoScalingGroupName=self.prefix, DesiredCapacity=0)
        returning = self.hook('TERMINATING', 'AutoScalingGroup', 'WarmPool', iid)
        targets = self.call('drained-before-' + state + '-reuse', 'elbv2', 'describe_target_health',
                            TargetGroupArn=o['tg'])['TargetHealthDescriptions']
        assert not any(row['Target']['Id'] == iid for row in targets), targets
        assert self.http(address) == active, 'reuse stopped the guest before its hook completed'
        self.complete(returning)
        reused = self.warm(iid, state)
        self.data['observations'][state] = {'instance': iid, 'initial': seeded, 'initial_pool': waiting,
            'reopened_pool': reopened, 'activated': active, 'reused_pool': reused,
            'launch_hook': launch, 'activation_hook': activation, 'reuse_hook': returning,
            'drained_targets': targets}
        self.save()
        self.asg('delete-' + state + '-pool', 'delete_warm_pool', AutoScalingGroupName=self.prefix, ForceDelete=True)
        deleting = self.hook('TERMINATING', 'WarmPool', 'EC2', iid)
        self.data['observations'][state]['force_delete_hook'] = deleting
        self.save()
        self.complete(deleting)
        self.wait('warm configuration and membership removed', self.pool,
                  lambda row: not row.get('WarmPoolConfiguration') and not row.get('Instances'), 240)
        self.wait('warm guest actually terminated', lambda: self.instance(iid),
                  lambda row: row['State']['Name'] == 'terminated', 180)
        assert self.http(address) is None, 'deleted warm guest still serving'
        self.data['observations'][state]['terminated'] = True
        self.save()

    def gauges(self, iid):
        since = datetime.now(timezone.utc)
        expected = {'GroupInServiceInstances': 0, 'GroupTotalInstances': 0,
                    'WarmPoolDesiredCapacity': 1, 'WarmPoolWarmedCapacity': 1,
                    'GroupAndWarmPoolTotalCapacity': 1}
        queries = [{'Id': 'm' + str(index), 'MetricStat': {'Metric': {'Namespace': 'AWS/AutoScaling',
                    'MetricName': name, 'Dimensions': [{'Name': 'AutoScalingGroupName', 'Value': self.prefix}]},
                    'Period': 60, 'Stat': 'Average'}} for index, name in enumerate(expected)]
        wanted = {'m' + str(index): value for index, value in enumerate(expected.values())}
        for key, name, value in (('cpu_instance', 'InstanceId', iid),
                                 ('cpu_group', 'AutoScalingGroupName', self.prefix)):
            queries.append({'Id': key, 'MetricStat': {'Metric': {'Namespace': 'AWS/EC2',
                'MetricName': 'CPUUtilization', 'Dimensions': [{'Name': name, 'Value': value}]},
                'Period': 60, 'Stat': 'Average'}})

        def observed():
            return self.client('cloudwatch').get_metric_data(MetricDataQueries=queries,
                StartTime=since, EndTime=datetime.now(timezone.utc) + timedelta(minutes=1))['MetricDataResults']

        def matches(rows):
            return all(any(row['Id'] == key and any(at >= since and value == expected_value
                       for at, value in zip(row['Timestamps'], row['Values'])) for row in rows)
                       for key, expected_value in wanted.items()) and any(
                       row['Id'] == 'cpu_instance' and any(at >= since for at in row.get('Timestamps', []))
                       for row in rows)

        rows = self.wait('actual warm capacity and instance CPU samples', observed, matches, 150)
        self.data['observations']['warm_metrics'] = {'instance': iid, 'since': since, 'results': rows}
        self.save()
        assert not any(row['Id'] == 'cpu_group' and any(at >= since for at in row.get('Timestamps', []))
                       for row in rows), 'warm-only guest contributed to active group CPU: ' + str(rows)

    def cleanup(self):
        if 'group' in self.owned and self.group():
            self.pool()
        super().cleanup()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--upgrade-from-binary', type=Path)
    parser.add_argument('--elbv2-node-executable', type=Path, default=Path('bin/stackd-elbv2-node-integration'))
    parser.add_argument('--raw-image', type=Path, default=Path('/tmp/stackd-ubuntu-24.04-server.raw'))
    parser.add_argument('--bios', type=Path, default=Path('/usr/share/seabios/bios-256k.bin'))
    parser.add_argument('--state-directory', type=Path, required=True)
    parser.add_argument('--port', type=int, default=15954)
    parser.add_argument('--gateway', default='10.194.20.1')
    parser.add_argument('--pool-state', nargs='+', choices=['Stopped', 'Running', 'Hibernated'],
                        default=['Stopped', 'Running', 'Hibernated'])
    parser.add_argument('--output', type=Path, default=Path('testdata/integration/autoscaling_warm_pool_guest.json'))
    args = parser.parse_args()
    args.binary = args.binary.resolve()
    smoke = Smoke(args)
    try:
        smoke.run()
    except BaseException as error:
        smoke.data['failure'] = {'type': type(error).__name__, 'message': str(error)}
        smoke.save()
        raise
    finally:
        try:
            smoke.cleanup()
        except BaseException as error:
            smoke.data['cleanup']['failure'] = {'type': type(error).__name__, 'message': str(error)}
            smoke.save()
            raise
        finally:
            smoke.stop()
    print(json.dumps({'observations': smoke.data['observations'], 'cleanup': smoke.data['cleanup']}, default=str))
