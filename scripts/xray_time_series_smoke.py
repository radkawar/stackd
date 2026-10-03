#!/usr/bin/env python3
"""Local signed SDK time-series workflow, retained SQLite and pagination recovery."""
import hashlib
import json
import os
from pathlib import Path
import socket
import sys
import tempfile
from datetime import datetime, timezone
import urllib.request
import uuid

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts/aws'))
from stackd_process import StackdProcess


def main():
    state = Path(tempfile.mkdtemp(prefix='stackd-xray-series-'))
    process = StackdProcess(state)
    fixture = json.loads((ROOT/'testdata/aws/xray/time_series_west.json').read_text())
    batches = [r for r in fixture['observations'] if r['operation'] == 'put_trace_segments']
    clock = datetime.fromisoformat(batches[0]['at']).timestamp()-1
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        port = sock.getsockname()[1]
    endpoint = f'http://127.0.0.1:{port}'
    environment = {k:v for k,v in os.environ.items() if not k.startswith('AWS_')}
    environment['AWS_EC2_METADATA_DISABLED'] = 'true'
    command = [str(ROOT/'bin/stackd'), '-listen', f'127.0.0.1:{port}', '-public-endpoint', endpoint,
               '-database', str(state/'state.sqlite'), '-clock-start', datetime.fromtimestamp(clock,timezone.utc).isoformat()]
    report = {'scope':'Local executable; signed SDK, native-calibrated historical statistics, SQLite restart and local pagination bound.',
              'binary_sha256':hashlib.sha256((ROOT/'bin/stackd').read_bytes()).hexdigest(),
              'sources':['testdata/aws/xray/time_series_west.json','testdata/aws/xray/time_series_settled.json'],
              'observations':[], 'controllers':process.runs}
    config = Config(retries={'total_max_attempts':1},connect_timeout=5,read_timeout=30)
    def client(service, key='test', secret='test', region='us-west-2'):
        return boto3.client(service, endpoint_url=endpoint,region_name=region,aws_access_key_id=key,
                            aws_secret_access_key=secret,config=config)
    def advance(seconds):
        nonlocal clock
        request=urllib.request.Request(endpoint+'/_stackd/clock',data=json.dumps({'advance':f'{seconds:.6f}s'}).encode(),headers={'Content-Type':'application/json'})
        with urllib.request.urlopen(request,timeout=30) as response: response.read()
        clock += seconds
    def reject(fn, code, **kw):
        try: fn(**kw)
        except ClientError as error:
            assert error.response['Error']['Code']==code, error.response
        else: raise AssertionError('Expected '+code)
    def clean(response):
        return {k:v for k,v in response.items() if k!='ResponseMetadata'}
    x, iam = client('xray'), client('iam')
    groups=[]; user=None; key=None
    try:
        process.start(command,endpoint,environment=environment)
        name=fixture['prefix']
        groups.append(x.create_group(GroupName=name,FilterExpression='service("'+name+'-front")')['Group']['GroupARN'])
        for batch in batches:
            advance(datetime.fromisoformat(batch['at']).timestamp()-clock)
            result=x.put_trace_segments(**batch['input'])
            assert result['UnprocessedTraceSegments']==[], result
        query={'StartTime':fixture['receipt_anchor']-60,'EndTime':fixture['receipt_anchor']+180,
               'EntitySelectorExpression':'service("'+name+'-front")','Period':60}
        before=clean(x.get_time_series_service_statistics(**query))
        points=before['TimeSeriesServiceStatistics']
        assert [p['ServiceSummaryStatistics']['TotalCount'] for p in points]==[2,2], points
        assert [p['ServiceSummaryStatistics']['TotalResponseTime'] for p in points]==[1.4,3.75], points
        assert [int(p['Timestamp'].timestamp()) for p in points]==[fixture['receipt_anchor']+120,fixture['receipt_anchor']+60]
        report['observations'].append({'case':'native-calibrated-service-buckets','response':before})
        user='series-reader'
        iam.create_user(UserName=user)
        credential=iam.create_access_key(UserName=user)['AccessKey'];key=credential['AccessKeyId']
        reader=client('xray',key,credential['SecretAccessKey'])
        reject(reader.get_time_series_service_statistics,'AccessDeniedException',**query)
        policy={'Version':'2012-10-17','Statement':[{'Effect':'Allow','Action':'xray:GetTimeSeriesServiceStatistics','Resource':'*'}]}
        iam.put_user_policy(UserName=user,PolicyName='read',PolicyDocument=json.dumps(policy))
        assert clean(reader.get_time_series_service_statistics(**query))==before
        process.stop();process.start(command,endpoint,environment=environment)
        assert clean(reader.get_time_series_service_statistics(**query))==before
        iam.delete_user_policy(UserName=user,PolicyName='read')
        reject(reader.get_time_series_service_statistics,'AccessDeniedException',**query)
        report['observations'].append({'case':'sqlite-restart-and-current-iam','denied_without_policy':True,'allowed_with_policy':True,'identical_after_restart':True,'revoked_after_restart':True})
        groupquery={k:v for k,v in query.items() if k!='EntitySelectorExpression'}
        groupquery['GroupARN']=groups[0]
        x.update_group(GroupARN=groups[0],FilterExpression='service("'+name+'-front") { fault }')
        assert x.get_time_series_service_statistics(**groupquery)['ContainsOldGroupVersions'] is True
        reject(x.get_time_series_service_statistics,'NotImplementedException',**query,ForecastStatistics=True)
        assert client('xray',region='eu-west-1').get_time_series_service_statistics(**query)['TimeSeriesServiceStatistics']==[]
        report['observations'].append({'case':'group-history-forecast-and-region','old_membership_retained':True,'forecast_explicitly_unsupported':True,'region_isolated':True})
        paging='series-paging'
        groups.append(x.create_group(GroupName=paging,FilterExpression='service("'+paging+'")')['Group']['GroupARN'])
        page_start=clock
        for i in range(1001):
            stamp=clock-2
            document={'name':paging,'trace_id':f'1-{int(stamp):08x}-'+uuid.uuid4().hex[:24],
                      'id':uuid.uuid4().hex[:16],'start_time':stamp,'end_time':stamp+1.25}
            accepted=x.put_trace_segments(TraceSegmentDocuments=[json.dumps(document)])
            assert accepted['UnprocessedTraceSegments']==[]
            advance(60)
        pagequery={'StartTime':page_start-60,'EndTime':clock+60,'GroupARN':groups[1],'Period':60}
        first=x.get_time_series_service_statistics(**pagequery)
        assert len(first['TimeSeriesServiceStatistics'])==1000 and first.get('NextToken')
        token=first['NextToken']
        changed=dict(pagequery,Period=300,NextToken=token)
        reject(x.get_time_series_service_statistics,'InvalidRequestException',**changed)
        process.stop();process.start(command,endpoint,environment=environment)
        second=x.get_time_series_service_statistics(**pagequery,NextToken=token)
        assert not second.get('NextToken') and len(second['TimeSeriesServiceStatistics'])==1
        allpoints=first['TimeSeriesServiceStatistics']+second['TimeSeriesServiceStatistics']
        timestamps=[int(p['Timestamp'].timestamp()) for p in allpoints]
        expected=[int(page_start//60)*60+60*(i+1) for i in range(1001)][::-1]
        assert timestamps==expected
        assert all(p['EdgeSummaryStatistics']['TotalCount']==1 and p['EdgeSummaryStatistics']['TotalResponseTime']==1.25 for p in allpoints)
        report['observations'].append({'case':'pagination-across-executable-restart','page_counts':[1000,1],'exact_ordered_endpoints':True,'no_duplicate_or_missing_bucket':True,'changed_query_token_rejected':True})
        report['status']='passed'
    finally:
        removed = False
        try:
            if process.process is not None and process.process.poll() is None:
                for arn in groups: x.delete_group(GroupARN=arn)
                if key: iam.delete_access_key(UserName=user,AccessKeyId=key)
                if user: iam.delete_user(UserName=user)
                removed = True
        finally:
            try:
                process.stop()
            finally:
                report['cleanup']={'groups_and_reader_deleted':removed,'controllers_exited_zero':all(r.get('exit')==0 for r in process.runs),
                                   'traces':'Local trace documents remain in isolated temporary SQLite under normal retention; no native mutations.'}
                (state/'report.json').write_text(json.dumps(report,indent=2,default=str)+'\n')
                print(state/'report.json')
    if report.get('status')!='passed': raise RuntimeError('Smoke incomplete')
    (ROOT/'testdata/integration/xray_time_series.json').write_text(json.dumps(report,indent=2,default=str)+'\n')


if __name__=='__main__': main()
