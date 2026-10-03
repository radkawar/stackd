#!/usr/bin/env python3
"""Bounded exact-owned X-Ray statistics capture; trace documents expire in AWS.

No account, IAM, sampling, encryption or Insights configuration is changed.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import time
import uuid

import boto3
import botocore
from botocore.config import Config
from botocore.exceptions import ClientError


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--region', default='us-west-2')
    parser.add_argument("--account", required=True)
    args = parser.parse_args()
    if args.output.exists():
        raise RuntimeError('Refusing to overwrite retained evidence')
    os.umask(0o077)
    session = boto3.Session(region_name=args.region)
    config = Config(ignore_configured_endpoint_urls=True, parameter_validation=False,
                    retries={'total_max_attempts': 1}, connect_timeout=5, read_timeout=20)
    xray = session.client('xray', config=config)
    prefix = 'stackd-ts-' + uuid.uuid4().hex[:10]
    start = time.monotonic()
    data = {'captured_at': datetime.now(timezone.utc).isoformat(), 'prefix': prefix,
            'region': args.region, 'probe_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            'sources': ['https://docs.aws.amazon.com/xray/latest/api/API_GetTimeSeriesServiceStatistics.html'],
            'sdk': {'boto3': boto3.__version__, 'botocore': botocore.__version__},
            'bounds': {'api_calls': 100, 'seconds': 600, 'trace_documents': 8},
            'observations': [], 'cleanup': [], 'owned': {},
            'limitations': ['Submitted synthetic trace documents have no delete API and remain under AWS trace retention.',
                            'Forecasting is not enabled or calibrated. No existing resource is mutated.']}
    calls = 0
    group = None
    group_attempted = False

    def save():
        args.output.parent.mkdir(parents=True, exist_ok=True)
        temp = args.output.with_suffix('.json.tmp')
        temp.write_text(json.dumps(data, indent=2, default=str) + '\n')
        temp.replace(args.output)

    def call(operation, label, cleanup=False, **request):
        nonlocal calls
        if not cleanup and (calls >= 94 or time.monotonic() - start > 550):
            raise RuntimeError('Native probe bound reached; reserving cleanup calls')
        calls += 1
        row = {'case': label, 'operation': operation, 'input': request,
               'at': datetime.now(timezone.utc).isoformat()}
        try:
            row['output'] = getattr(xray, operation)(**request)
            row['code'] = 'Success'
        except ClientError as error:
            row['output'] = error.response
            row['code'] = error.response['Error']['Code']
        data['cleanup' if cleanup else 'observations'].append(row)
        save()
        return row

    def require(row):
        if row['code'] != 'Success':
            raise RuntimeError(row['case'] + ': ' + row['code'])
        return row['output']

    try:
        identity = session.client('sts', config=config).get_caller_identity()
        if identity['Account'] != args.account:
            raise RuntimeError('Unexpected native account')
        data['account'] = identity['Account']
        data['identity_arn'] = identity['Arn']
        destination = require(call('get_trace_segment_destination', 'destination-control'))
        if destination.get('Destination') != 'XRay':
            raise RuntimeError('Trace destination is not XRay; account settings remain unchanged')
        absent = call('get_group', 'owned-name-preflight', GroupName=prefix)
        if absent['code'] != 'InvalidRequestException':
            raise RuntimeError('Cannot establish absence of unique group name')
        data['owned']['group_name'] = prefix
        save()
        group_attempted = True
        created = require(call('create_group', 'group-create', GroupName=prefix,
                               FilterExpression='service("' + prefix + '-front")',
                               InsightsConfiguration={'InsightsEnabled': False, 'NotificationsEnabled': False},
                               Tags=[{'Key': 'stackd-probe', 'Value': prefix}]))
        group = created['Group']['GroupARN']
        data['owned']['group_arn'] = group
        save()
        anchor = int(time.time() // 60) * 60 - 600
        data['anchor'] = anchor
        documents = []
        ids = []
        for offset, duration, status in ((10, 1.25, 200), (59.8, 2.5, 400), (60.2, .4, 429), (130, 1., 500)):
            stamp = anchor + offset
            trace = f'1-{int(stamp):08x}-' + uuid.uuid4().hex[:24]
            ids.append(trace)
            root, remote, child = (uuid.uuid4().hex[:16] for _ in range(3))
            flags = {'error': 400 <= status < 500, 'throttle': status == 429, 'fault': status >= 500}
            downstream = dict(name=prefix+'-back', id=child, parent_id=remote, trace_id=trace,
                              start_time=stamp+.1, end_time=stamp+duration-.1,
                              http={'response': {'status': status}}, **flags)
            front = dict(name=prefix+'-front', id=root, trace_id=trace, start_time=stamp,
                         end_time=stamp+duration, http={'response': {'status': status}}, **flags,
                         subsegments=[dict(name=prefix+'-back', id=remote, namespace='remote',
                                           start_time=stamp+.05, end_time=stamp+duration-.05,
                                           http={'response': {'status': status}}, **flags)])
            documents += [front, downstream]
        data['owned']['trace_ids'] = ids
        data['documents'] = documents
        save()
        receipt = int(time.time() // 60) * 60
        data['receipt_anchor'] = receipt
        for batch in range(2):
            if batch:
                time.sleep(max(0, receipt+61-time.time()))
            inserted = require(call('put_trace_segments', 'ingest-owned-traces-'+str(batch),
                                    TraceSegmentDocuments=[json.dumps(v) for v in documents[batch*4:batch*4+4]]))
            if inserted.get('UnprocessedTraceSegments'):
                raise RuntimeError('Native trace ingestion rejected owned documents')
        window = {'StartTime': anchor, 'EndTime': receipt+180, 'GroupARN': group}
        deadline = time.monotonic()+180
        while True:
            observed = require(call('get_time_series_service_statistics', 'await-owned-statistics', Period=60, **window))
            if sum(p.get('EdgeSummaryStatistics', {}).get('TotalCount', 0) for p in observed.get('TimeSeriesServiceStatistics', [])) == 4:
                break
            if time.monotonic() >= deadline:
                data['inconclusive'] = 'Both trace batches did not become visible in the bounded window'
                break
            time.sleep(10)
        call('batch_get_traces', 'trace-control', TraceIds=ids)
        call('get_service_graph', 'graph-control', **window)
        for period in (None, 0, -1, 1, 10, 30, 60, 61, 120, 300, 3600):
            fields = {} if period is None else {'Period': period}
            call('get_time_series_service_statistics', 'period-'+str(period), **window, **fields)
        for label, begin, end in (('unaligned', receipt+7, receipt+137), ('exact-boundary', receipt+60, receipt+120),
                                  ('document-time', anchor, anchor+180), ('receipt-time', receipt, receipt+180),
                                  ('empty', anchor-300, anchor-120), ('zero-window', receipt, receipt),
                                  ('reversed', receipt+120, receipt)):
            call('get_time_series_service_statistics', label, StartTime=begin, EndTime=end, GroupARN=group, Period=60)
        for selector in ('service("'+prefix+'-front")', 'service("'+prefix+'-back")',
                         'service(id(name: "'+prefix+'-front"))',
                         'id(name: "'+prefix+'-front")', 'id(0)',
                         'edge("'+prefix+'-front", "'+prefix+'-back")',
                         'edge(id(name: "'+prefix+'-front"), id(name: "'+prefix+'-back"))',
                         'service()', 'edge()', 'service("'+prefix+'-front") { fault }',
                         'service("missing-owned-service")'):
            call('get_time_series_service_statistics', 'selector-'+selector, **window, Period=60, EntitySelectorExpression=selector)
        call('get_time_series_service_statistics', 'invalid-token', **window, Period=60, NextToken='not-a-token')
        call('get_time_series_service_statistics', 'group-name', StartTime=anchor, EndTime=receipt+180, GroupName=prefix, Period=60)
        require(call('update_group', 'replace-group-filter', GroupARN=group, FilterExpression='service("'+prefix+'-front") { fault }'))
        call('get_time_series_service_statistics', 'old-group-membership', **window, Period=60)
        data['complete'] = True
    finally:
        if group_attempted:
            reference = {'GroupARN': group} if group is not None else {'GroupName': prefix}
            call('delete_group', 'delete-owned-group', cleanup=True, **reference)
            absent = call('get_group', 'verify-owned-group-absent', cleanup=True, **reference)
            data['cleanup_verified'] = absent['code'] == 'InvalidRequestException'
        data['api_calls'] = calls+1
        data['elapsed_seconds'] = time.monotonic()-start
        save()
    if not data.get('cleanup_verified'):
        raise RuntimeError('Owned group cleanup not verified')
    print(args.output)


if __name__ == '__main__':
    main()
