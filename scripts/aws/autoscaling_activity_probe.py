#!/usr/bin/env python3
"""Read activity-filter behavior from one previously cleaned owned ASG history.

No resource creation, account-wide inventory, or mutation. Reuse the source
capture's exact group and the shared signed recorder/account guard.
"""
import argparse
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path

from ebs_encryption_probe import Capture, CONFIG


def capture(args):
    source = json.loads(args.source_capture.read_text())
    group = source['owned']['asgs'][0]
    if not source.get('cleanup', {}).get('complete'):
        raise RuntimeError('Source capture has not completed owned-resource cleanup')
    recorder = Capture(args)
    if source['account'] != recorder.data['account'] or source['region'] != args.region:
        raise RuntimeError('Source history scope differs from the authorized capture scope')
    recorder.clients['autoscaling'] = recorder.session.client('autoscaling', config=CONFIG)
    recorder.data.pop('payload', None)
    recorder.data.update(scope=__doc__, source_capture=str(args.source_capture),
        reference_group=group, owned={}, documentation=[
            'https://docs.aws.amazon.com/autoscaling/ec2/APIReference/API_DescribeScalingActivities.html'])
    base = {'AutoScalingGroupName': group, 'IncludeDeletedGroups': True, 'MaxRecords': 100}

    def observe(label, filters=None, **overrides):
        parameters = dict(base, **overrides)
        if parameters.get('AutoScalingGroupName') is None:
            parameters.pop('AutoScalingGroupName')
        if filters is not None:
            parameters['Filters'] = filters
        return recorder.observe(label, 'autoscaling', 'describe_scaling_activities', parameters)

    baseline = observe('owned-deleted-history')
    activities = baseline.get('Activities', [])
    if not activities or baseline.get('NextToken'):
        raise RuntimeError('Expected a nonempty bounded owned activity history')
    anchor = min(row['StartTime'] for row in activities)
    if isinstance(anchor, str):
        anchor = datetime.fromisoformat(anchor)
    anchor = anchor.astimezone(timezone.utc)
    stamp = anchor.isoformat().replace('+00:00', 'Z')
    before = (anchor - timedelta(microseconds=1)).isoformat().replace('+00:00', 'Z')
    after = (anchor + timedelta(microseconds=1)).isoformat().replace('+00:00', 'Z')
    recorder.data['anchor'] = stamp
    formats = {
        'utc': stamp,
        'offset': anchor.astimezone(timezone(timedelta(hours=8))).isoformat(),
        'no-zone': anchor.replace(tzinfo=None).isoformat(),
        'space': anchor.replace(tzinfo=None).isoformat(sep=' '),
        'date-only': anchor.date().isoformat(),
        'basic': anchor.strftime('%Y%m%dT%H%M%SZ'),
        'lowercase': stamp.lower(),
        'offset-basic': anchor.astimezone(timezone(timedelta(hours=8))).strftime('%Y-%m-%dT%H:%M:%S.%f%z'),
        'epoch': str(int(anchor.timestamp())),
        'blank': '', 'invalid': 'not-a-time', 'invalid-day': '2026-02-30T00:00:00Z',
        'leading-space': ' ' + stamp, 'trailing-space': stamp + ' ',
    }
    if args.edge_formats:
        formats = {
            'day-zero': '2026-09-00T12:00:00Z', 'day-32': '2026-09-32T12:00:00Z',
            'month-zero': '2026-00-27T12:00:00Z', 'month-13': '2026-13-27T12:00:00Z',
            'end-of-day': '2026-09-27T24:00:00Z', 'hour-24-nonzero': '2026-09-27T24:00:01Z',
            'leap-second': '2026-09-27T12:47:60Z', 'minute-60': '2026-09-27T12:60:00Z',
            'fraction-nine': anchor.strftime('%Y-%m-%dT%H:%M:%S.%f') + '001Z',
            'fraction-ten': anchor.strftime('%Y-%m-%dT%H:%M:%S.%f') + '0001Z',
            'fraction-comma': stamp.replace('.', ','),
            'short-fields': '2026-9-27T2:3:4Z', 'no-seconds': '2026-09-27T12:47Z',
            'offset-18': '2026-09-27T12:47:11+18:00', 'offset-over-18': '2026-09-27T12:47:11+18:01',
            'trailing-data': stamp + 'ignored',
        }
    for name in ('StartTimeLowerBound', 'StartTimeUpperBound'):
        for label, value in formats.items():
            observe(name + '-' + label, [{'Name': name, 'Values': [value]}])
        if args.edge_formats:
            continue
        for label, values in (('before', [before]), ('after', [after]), ('empty', []),
                              ('multiple', [before, after]), ('duplicates', [stamp, stamp])):
            observe(name + '-' + label, [{'Name': name, 'Values': values}])
        observe(name + '-duplicate-filters', [{'Name': name, 'Values': [before]},
                                             {'Name': name, 'Values': [after]}])
    lower = {'Name': 'StartTimeLowerBound', 'Values': [stamp]}
    upper = {'Name': 'StartTimeUpperBound', 'Values': [stamp]}
    observe('exact-inclusive-interval', [lower, upper])
    observe('reversed-interval', [{'Name': 'StartTimeLowerBound', 'Values': [after]},
                                  {'Name': 'StartTimeUpperBound', 'Values': [before]}])
    observe('status-and-time', [lower, {'Name': 'Status', 'Values': ['Successful']}])
    ids = [row['ActivityId'] for row in activities]
    observe('time-without-group-owned-ids', [lower], AutoScalingGroupName=None, ActivityIds=ids)
    observe('status-without-group-owned-ids', [{'Name': 'Status', 'Values': ['Successful']}],
            AutoScalingGroupName=None, ActivityIds=ids)
    observe('time-without-deleted-groups', [lower], IncludeDeletedGroups=False)
    page = observe('bounded-first-page', [lower], MaxRecords=1)
    if page.get('NextToken'):
        observe('bounded-next-page', [lower], MaxRecords=1, NextToken=page['NextToken'])
        observe('changed-bound-page-token', [upper], MaxRecords=1, NextToken=page['NextToken'])
        observe('changed-status-page-token', [{'Name': 'Status', 'Values': ['Failed']}],
                MaxRecords=1, NextToken=page['NextToken'])
        observe('changed-ids-page-token', [lower], ActivityIds=[ids[-1]],
                MaxRecords=1, NextToken=page['NextToken'])
        middle = sorted(row['StartTime'] for row in activities)[len(activities) // 2]
        observe('changed-middle-upper-page-token',
                [{'Name': 'StartTimeUpperBound', 'Values': [middle.isoformat()]}],
                MaxRecords=1, NextToken=page['NextToken'])
        observe('all-ids-with-page-token', [lower], ActivityIds=ids,
                MaxRecords=1, NextToken=page['NextToken'])
        for label, bound, maximum in (
            ('oldest-offset', anchor.isoformat(), 1),
            ('oldest-plus-millisecond', (anchor + timedelta(milliseconds=1)).isoformat(), 1),
            ('middle-z', middle.isoformat().replace('+00:00', 'Z'), 1),
            ('oldest-large-page', stamp, 100),
        ):
            observe('continuation-upper-' + label, [{'Name': 'StartTimeUpperBound', 'Values': [bound]}],
                    MaxRecords=maximum, NextToken=page['NextToken'])
    observe('all-ids-small-page', [lower], ActivityIds=ids, MaxRecords=1)
    observe('all-ids-invalid-token', [lower], ActivityIds=ids, NextToken='invalid')
    observe('ids-failed-status', [{'Name': 'Status', 'Values': ['Failed']}], ActivityIds=ids)
    observe('ids-future-lower', [{'Name': 'StartTimeLowerBound',
            'Values': [(anchor + timedelta(days=1)).isoformat()]}], ActivityIds=ids)
    recorder.data['cleanup'] = {'complete': True, 'boundary': 'Read-only exact-owned history; no resources created or mutated.'}
    recorder.save()
    print(json.dumps({'calls': len(recorder.data['calls']), 'group': group, 'cleanup': recorder.data['cleanup']}))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--account', required=True)
    parser.add_argument('--region', default='us-east-1')
    parser.add_argument('--source-capture', type=Path,
                        default=Path('.stackd/probes/autoscaling/warm_pool_suspended_launch_native.json'))
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--edge-formats', action='store_true')
    args = parser.parse_args()
    args.audit_only = args.cleanup_only = False
    capture(args)
