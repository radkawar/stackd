#!/usr/bin/env python3
"""Observe deleted/recreated async targets using signed SDK calls and real runtimes.

Example (never reuses or overwrites an existing state directory/report):
  python3 scripts/aws/lambda_async_deletion_smoke.py --binary bin/stackd \
    --telemetry-directory bin --state-directory /tmp/stackd-async-deletion-UNIQUE \
    --report testdata/integration/lambda_async_deletion_UNIQUE.json

The manual service clock advances real retry opportunities, not runtime results.
SQLite is inspected read-only to wait for completed scheduling transitions. SQS
receipts, not database rows, establish handler execution and destination delivery.
Native retry-enabled missing-alias aggregate drop evidence calibrates a scoped local
age-expiry rule, not an AWS terminal record, exact scheduling or six-hour guarantee.
Whole-function/fixed-version queued404 outcomes and fixed/alias postfailure404
outcomes have positive native calibration. Whole-function postfailure terminal
routing and exact recreation propagation timing remain explicitly unproven.

The deleted-dlq-before scenario preserves the retry-zero missing-DLQ diagnostic
after a positive normal-failure control. deleted-dlq-after additionally exercises
independent OnFailure/DLQ routing and current IAM delivery authority across retained
controller restarts. Full SQS attributes and SDK metric query responses are
retained; missing native receipts never establish an expected terminal fate.
"""
import argparse
import concurrent.futures
from datetime import datetime, timedelta, timezone
import hashlib
import io
import json
import os
from pathlib import Path
import socket
import sqlite3
import subprocess
import time
import urllib.request
import uuid
import zipfile

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

from stackd_process import StackdProcess


HANDLER = '''import boto3,json,os,time
from botocore.config import Config
sqs=boto3.client('sqs',endpoint_url=os.environ['PROOF_ENDPOINT'],config=Config(retries={'total_max_attempts':1}))
def handle(event,context):
    marker={'case':event['case'],'kind':event['kind'],'request_id':context.aws_request_id,'invoked_function_arn':context.invoked_function_arn,'function_version':context.function_version,'deployment':os.environ['DEPLOYMENT']}
    sqs.send_message(QueueUrl=os.environ['MARKER_QUEUE'],MessageBody=json.dumps(dict(marker,phase='entered')))
    if event['kind'] in ('hold','hold_fail'):
        deadline=time.monotonic()+120
        while time.monotonic()<deadline:
            rows=sqs.receive_message(QueueUrl=os.environ['GATE_QUEUE'],MaxNumberOfMessages=1,WaitTimeSeconds=1).get('Messages',[])
            if rows:
                release=json.loads(rows[0]['Body'])
                if release['case']!=event['case']: raise RuntimeError('mismatched owned release')
                sqs.delete_message(QueueUrl=os.environ['GATE_QUEUE'],ReceiptHandle=rows[0]['ReceiptHandle'])
                break
        else: raise RuntimeError('owned barrier release timed out')
        sqs.send_message(QueueUrl=os.environ['MARKER_QUEUE'],MessageBody=json.dumps(dict(marker,phase='released')))
    if event['kind'] in ('fail','hold_fail'): raise RuntimeError('intentional async control failure')
    return marker
'''


def require(value, message):
    if not value:
        raise AssertionError(message)


def plain(value):
    if isinstance(value, bytes):
        return value.decode('utf-8')
    if isinstance(value, datetime):
        return value.isoformat()
    raise TypeError(type(value).__name__)


def instant(value):
    # Go's SQLite TIMESTAMP encoding includes a separate offset and zone name.
    parts = value.split()
    if len(parts) == 4:
        value = parts[0] + 'T' + parts[1] + parts[2]
    return datetime.fromisoformat(value.replace('Z', '+00:00'))


class Proof:
    def __init__(self, args):
        self.args = args
        self.state = Path(args.state_directory).resolve()
        self.output = Path(args.report).resolve()
        require(not self.output.exists(), 'refusing to overwrite a prior report')
        self.state.mkdir(parents=True, exist_ok=False)
        self.database = self.state / 'state.sqlite'
        self.namespace = 'stackd-lambda-' + hashlib.sha256(str(self.database).encode()).hexdigest()[:24]
        self.owner = uuid.uuid4().hex
        self.prefix = 'async-deletion-' + self.owner[:10]
        (self.state / 'owner.json').write_text(json.dumps({'owner': self.owner, 'prefix': self.prefix}))
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0))
            self.port = sock.getsockname()[1]
        self.endpoint = f'http://127.0.0.1:{self.port}'
        self.compute_endpoint = f'http://host.docker.internal:{self.port}'
        self.controller = StackdProcess(self.state)
        self.pool = concurrent.futures.ThreadPoolExecutor(max_workers=1)
        self.clients = {name: boto3.client(name, endpoint_url=self.endpoint,
            region_name='us-east-1', aws_access_key_id='test', aws_secret_access_key='test',
            config=Config(retries={'total_max_attempts': 1}, connect_timeout=5, read_timeout=150))
            for name in ('lambda', 'iam', 'sqs', 'cloudwatch')}
        self.fn, self.iam, self.sqs = (self.clients[x] for x in ('lambda', 'iam', 'sqs'))
        self.queues = {}
        self.functions = {}
        self.published = {}
        self.role = None
        self.held = None
        self.report = {'schema_version': 1, 'prefix': self.prefix, 'endpoint': self.endpoint,
            'binary': str(Path(args.binary).resolve()),
            'binary_sha256': hashlib.file_digest(Path(args.binary).open('rb'), 'sha256').hexdigest(),
            'runtime': 'public.ecr.aws/lambda/python:3.12',
            'evidence_scope': 'Local executable observations only. Positive native captures calibrate observed counts/status/routes, not exact local scheduling or six-hour fate. Whole-function deletion after handler failure has aggregate drop evidence but no terminal route record; its scheduling/route fate and exact recreation propagation timing remain unproven. Bounded absence establishes neither pending state nor permanent loss.',
            'controls': {}, 'cases': {}, 'receipts': [], 'controllers': self.controller.runs,
            'clock_advances': [], 'cleanup': [], 'assertions': [],
            'sources': ['docs/lambda.md#resource-policies-and-asynchronous-delivery', 'testdata/aws/lambda/qualified_deletion_retry.json',
                'testdata/aws/lambda/async_deletion_lifecycle_retry.json',
                'testdata/aws/lambda/async_deletion_analysis.json',
                'testdata/aws/lambda/async_deletion_metrics.json',
                'testdata/aws/lambda/async_deletion_sources.json',
                'testdata/aws/lambda/async_deleted_targets_analysis.json',
                'testdata/aws/lambda/async_recreation_order_analysis.json',
                'https://docs.aws.amazon.com/lambda/latest/dg/python-image.html',
                'https://docs.aws.amazon.com/lambda/latest/dg/configuration-versions.html',
                'https://docs.aws.amazon.com/lambda/latest/dg/invocation-async-error-handling.html'],
            'started_at': datetime.now(timezone.utc).isoformat()}

    def docker(self, *arguments):
        result = subprocess.run(['docker', '--host', self.args.docker_host, *arguments],
            capture_output=True, text=True, check=True, timeout=30)
        return result.stdout.strip()

    def runtime_evidence(self):
        image = json.loads(self.docker('image', 'inspect', self.report['runtime']))[0]
        require(image['Config']['Entrypoint'] == ['/lambda-entrypoint.sh'], 'installed image is not the official Lambda runtime')
        self.report['runtime_image'] = {'id': image['Id'], 'repo_digests': image['RepoDigests'],
            'entrypoint': image['Config']['Entrypoint']}
        ids = self.docker('ps', '-aq', '--filter', 'label=io.stackd.lambda.instance=' + self.namespace).split()
        rows = json.loads(self.docker('inspect', *ids)) if ids else []
        evidence = []
        for row in rows:
            labels = row['Config']['Labels']
            require(labels.get('io.stackd.lambda.instance') == self.namespace, 'Docker namespace mismatch')
            if 'AWS_EXECUTION_ENV=AWS_Lambda_python3.12' not in row['Config'].get('Env', []):
                continue
            require(labels.get('io.stackd.function', '').split(':function:')[-1].split(':')[0] in self.functions,
                'runtime function ownership mismatch')
            require(row['Image'] == image['Id'], 'executing container differs from installed official Python image')
            evidence.append({'id': row['Id'], 'image': row['Image'],
                'entrypoint': row['Config']['Entrypoint'], 'labels': labels,
                'state': row['State']['Status']})
        require(evidence, 'held execution has no actual official Lambda runtime container')
        return evidence

    def start(self):
        environment = {key: value for key, value in os.environ.items() if not key.startswith('AWS_')}
        environment['AWS_EC2_METADATA_DISABLED'] = 'true'
        command = [str(Path(self.args.binary).resolve()), '-listen', f'0.0.0.0:{self.port}',
            '-public-endpoint', self.endpoint, '-database', str(self.database),
            '-clock-start', '2026-09-30T12:00:00Z', '-docker-host', self.args.docker_host,
            '-compute-endpoint', self.compute_endpoint, '-lambda-telemetry-directory',
            str(Path(self.args.telemetry_directory).resolve()), '-lambda-keep-alive', '0']
        self.controller.start(command, self.endpoint, environment=environment, timeout=90)
        # A parent may atomically replace the executable while this probe runs.
        # /proc identifies the actual inode used by each restarted controller.
        with Path(f'/proc/{self.controller.process.pid}/exe').open('rb') as executable:
            self.controller.runs[-1]['binary_sha256'] = hashlib.file_digest(executable, 'sha256').hexdigest()
        with sqlite3.connect(f'file:{self.database}?mode=ro', uri=True) as connection:
            self.controller.runs[-1]['sqlite_schema_version'] = connection.execute('PRAGMA user_version').fetchone()[0]

    def control(self, path, payload=None):
        request = urllib.request.Request(self.endpoint + path,
            data=json.dumps(payload).encode() if payload is not None else b'',
            headers={'Content-Type': 'application/json'})
        with urllib.request.urlopen(request, timeout=30) as response:
            return json.load(response)

    def now(self):
        with urllib.request.urlopen(self.endpoint + '/_stackd/clock', timeout=5) as response:
            return json.load(response)['time']

    def advance(self, seconds):
        require(seconds >= 0, 'service time cannot go backwards')
        value = self.control('/_stackd/clock', {'advance': f'{seconds:.9f}s'})
        self.report['clock_advances'].append({'seconds': seconds, 'result': value})
        self.control('/_stackd/jobs/drain?limit=4096')

    def wait(self, predicate, label, timeout=60):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            result = predicate()
            if result:
                return result
            time.sleep(.1)
        raise TimeoutError(label)

    def collect(self):
        for kind in ('marker', 'destination', 'replacement-destination', 'legacy-dlq'):
            for message in self.sqs.receive_message(QueueUrl=self.queues[kind]['url'],
                    MaxNumberOfMessages=10, WaitTimeSeconds=0,
                    MessageAttributeNames=['All'], MessageSystemAttributeNames=['All']).get('Messages', []):
                self.report['receipts'].append({'queue': kind, 'service_time': self.now(),
                    'observed_at': datetime.now(timezone.utc).isoformat(),
                    'message_id': message['MessageId'], 'body': json.loads(message['Body']),
                    'raw_body': message['Body'], 'message_attributes': message.get('MessageAttributes', {}),
                    'system_attributes': message.get('Attributes', {})})
                self.sqs.delete_message(QueueUrl=self.queues[kind]['url'], ReceiptHandle=message['ReceiptHandle'])

    def receipts(self, case, kind='marker', phase=None):
        self.collect()
        result = []
        for receipt in self.report['receipts']:
            body = receipt['body']
            event = body if kind in ('marker', 'dlq') else body.get('requestPayload', {})
            matching_queue = (receipt['queue'] == 'marker' if kind == 'marker' else
                receipt['queue'] == 'legacy-dlq' if kind == 'dlq' else
                receipt['queue'] in ('destination', 'replacement-destination'))
            if matching_queue and event.get('case') == case and (phase is None or body.get('phase') == phase):
                result.append(body)
        return result

    def row(self, request_id):
        with sqlite3.connect(f'file:{self.database}?mode=ro', uri=True) as connection:
            connection.row_factory = sqlite3.Row
            row = connection.execute('SELECT * FROM lambda_invocations WHERE request_id=?', (request_id,)).fetchone()
            return dict(row) if row else None

    def settled(self, request_id):
        row = self.row(request_id)
        return {'row': row} if row is None or row['state'] != 'in-flight' else None

    def snapshot(self, case):
        row = self.wait(lambda: self.settled(case['request_id']), 'invocation scheduling transition')['row']
        case.setdefault('snapshots', []).append({'service_time': self.now(), 'row': row})
        return row

    def drive(self, case, horizon=600):
        started = instant(case['accepted_service_time'])
        for _ in range(40):
            row = self.snapshot(case)
            self.collect()
            if row is None or row['state'] == 'completed':
                break
            now = instant(self.now())
            due = instant(row['due'])
            elapsed = (now - started).total_seconds()
            if elapsed >= horizon or (due - started).total_seconds() > horizon:
                if elapsed < horizon:
                    self.advance(horizon - elapsed)
                    self.snapshot(case)
                break
            self.advance(max(0, (due - now).total_seconds()))
            time.sleep(.2)
        else:
            raise RuntimeError('too many scheduling transitions')
        # Outcome delivery runs separately from the invocation commit.
        self.control('/_stackd/jobs/drain?limit=4096')
        time.sleep(.4)
        case['runtime_markers'] = self.receipts(case['name'], phase='entered')
        case['destinations'] = self.receipts(case['name'], 'destination')
        case['dlq_receipts'] = [row for row in self.report['receipts']
            if row['queue'] == 'legacy-dlq' and row['body'].get('case') == case['name']]
        case['destination_receipts'] = [row for row in self.report['receipts'] if row['queue'] in ('destination', 'replacement-destination')
            and row['body'].get('requestPayload', {}).get('case') == case['name']]
        case['observed_through_service_time'] = self.now()
        case['last_retained_row'] = self.row(case['request_id'])
        for marker in case['runtime_markers']:
            require(marker['request_id'] == case['request_id'], 'accepted request identity changed at runtime')
            require(marker['invoked_function_arn'] == case['requested_arn'], 'requested ARN changed at runtime')
        for destination in case['destinations']:
            request = destination['requestContext']
            require(request['requestId'] == case['request_id'], 'accepted request identity changed at destination')
            expected = case['requested_arn'] + (':$LATEST' if not case['qualifier'] else '')
            require(request['functionArn'] == expected, 'requested ARN changed at destination')
        return case

    def setup(self):
        for kind in ('marker', 'destination', 'replacement-destination', 'legacy-dlq', 'gate'):
            name = self.prefix + '-' + kind
            url = self.sqs.create_queue(QueueName=name, tags={'SmokeOwner': self.owner})['QueueUrl']
            arn = self.sqs.get_queue_attributes(QueueUrl=url, AttributeNames=['QueueArn'])['Attributes']['QueueArn']
            self.queues[kind] = {'url': url, 'arn': arn, 'name': name}
        self.role = self.iam.create_role(RoleName=self.prefix, Tags=[{'Key': 'SmokeOwner', 'Value': self.owner}],
            AssumeRolePolicyDocument=json.dumps({'Version': '2012-10-17', 'Statement': [
                {'Effect': 'Allow', 'Principal': {'Service': 'lambda.amazonaws.com'}, 'Action': 'sts:AssumeRole'}]}))['Role']['Arn']
        self.set_runtime_policy()
        package = io.BytesIO()
        with zipfile.ZipFile(package, 'w') as archive:
            archive.writestr('handler.py', HANDLER)
        self.package = package.getvalue()

    def set_runtime_policy(self, deny_dlq=False, deny_destination=False):
        policy = {'Version': '2012-10-17', 'Statement': [{'Effect': 'Allow',
            'Action': ['sqs:SendMessage', 'sqs:ReceiveMessage', 'sqs:DeleteMessage'],
            'Resource': [row['arn'] for row in self.queues.values()]}]}
        if deny_dlq:
            policy['Statement'].append({'Effect': 'Deny', 'Action': 'sqs:SendMessage',
                'Resource': self.queues['legacy-dlq']['arn']})
        if deny_destination:
            policy['Statement'].append({'Effect': 'Deny', 'Action': 'sqs:SendMessage',
                'Resource': self.queues['destination']['arn']})
        request = {'RoleName': self.prefix, 'PolicyName': 'runtime', 'PolicyDocument': json.dumps(policy)}
        return {'request': request, 'response': self.iam.put_role_policy(**request)}

    def environment(self, deployment):
        return {'Variables': {'DEPLOYMENT': deployment, 'PROOF_ENDPOINT': self.compute_endpoint,
            'MARKER_QUEUE': self.queues['marker']['url'].replace(self.endpoint, self.compute_endpoint),
            'GATE_QUEUE': self.queues['gate']['url'].replace(self.endpoint, self.compute_endpoint)}}

    def create(self, name, deployment):
        row = self.fn.create_function(FunctionName=name, Runtime='python3.12', Handler='handler.handle',
            Code={'ZipFile': self.package}, Role=self.role, Timeout=130, MemorySize=128,
            Environment=self.environment(deployment), DeadLetterConfig={'TargetArn': self.queues['legacy-dlq']['arn']},
            Publish=True, Tags={'SmokeOwner': self.owner})
        self.functions[name] = row['FunctionArn']
        self.published[name] = row['Version']
        self.report.setdefault('function_creations', []).append(row)
        self.ready(name)
        self.fn.put_function_concurrency(FunctionName=name, ReservedConcurrentExecutions=1)
        return row

    def ready(self, name):
        def ready():
            row = self.fn.get_function_configuration(FunctionName=name)
            require(row.get('State') != 'Failed' and row.get('LastUpdateStatus') != 'Failed', str(row))
            return row.get('State') == 'Active' and row.get('LastUpdateStatus', 'Successful') == 'Successful'
        self.wait(ready, 'official runtime readiness', 90)

    def config(self, name, qualifier, retries=2, age=240, destination='destination', apply=True):
        args = {'FunctionName': name, 'MaximumRetryAttempts': retries, 'MaximumEventAgeInSeconds': age,
            'DestinationConfig': {key: {'Destination': self.queues[destination]['arn']} for key in ('OnSuccess', 'OnFailure')}
                if destination else {}}
        if qualifier:
            args['Qualifier'] = qualifier
        result = self.fn.put_function_event_invoke_config(**args)
        if apply:
            self.advance(120)
        return {key: value for key, value in result.items() if key != 'ResponseMetadata'}

    def config_snapshot(self, name, qualifier):
        with sqlite3.connect(f'file:{self.database}?mode=ro', uri=True) as connection:
            connection.row_factory = sqlite3.Row
            row = connection.execute('SELECT * FROM lambda_event_invoke_configs WHERE function_name=? AND qualifier=?',
                (name, qualifier)).fetchone()
            return {'service_time': self.now(), 'retained_config': dict(row) if row else None}

    def route_control(self, label, name, qualifier, destination):
        case = self.accept(label, name, qualifier)
        self.report['controls'][label] = case
        self.drive(case)
        self.require_success_route(case, destination)
        return label

    def require_success_route(self, case, destination):
        rows = case['destination_receipts']
        require(len(rows) == 1 and rows[0]['queue'] == destination, 'applied destination consumer control mismatch')
        body = rows[0]['body']
        require(body['requestContext']['condition'] == 'Success' and body['requestContext']['approximateInvokeCount'] == 1
            and body['responseContext']['statusCode'] == 200, 'applied destination success projection mismatch')

    def invoke(self, name, qualifier, event, asynchronous=False):
        args = {'FunctionName': name, 'Payload': json.dumps(event).encode(),
            'InvocationType': 'Event' if asynchronous else 'RequestResponse'}
        if qualifier:
            args['Qualifier'] = qualifier
        row = self.fn.invoke(**args)
        row['Payload'] = row['Payload'].read().decode()
        return row

    def accept(self, label, name, qualifier, kind='success'):
        accepted_time = self.now()
        event = {'case': label, 'kind': kind}
        row = self.invoke(name, qualifier, event, asynchronous=True)
        require(row['StatusCode'] == 202 and row['Payload'] == '' and 'FunctionError' not in row and 'ExecutedVersion' not in row,
            'asynchronous acceptance shape changed')
        request_id = row['ResponseMetadata']['RequestId']
        require(request_id, 'acceptance missing request identity')
        return {'name': label, 'function': name, 'qualifier': qualifier,
            'requested_arn': self.functions[name] + (':' + qualifier if qualifier else ''),
            'request_id': request_id, 'accepted_service_time': accepted_time, 'acceptance': row,
            'payload': event, 'payload_raw': json.dumps(event)}

    def hold(self, name, qualifier, label):
        self.held = {'case': label, 'future': self.pool.submit(self.invoke, name, qualifier, {'case': label, 'kind': 'hold'})}
        def entered():
            markers = self.receipts(label, phase='entered')
            if not markers and self.held['future'].done():
                try:
                    response = self.held['future'].result()
                except ClientError as error:
                    response = {'error': error.response}
                self.report.setdefault('barrier_failures', []).append({'case': label, 'response': response})
                raise RuntimeError('holder finished without an SQS entry marker: ' + str(response))
            return markers
        markers = self.wait(entered, 'real held runtime marker')
        require(not self.held['future'].done(), 'runtime did not remain held')
        try:
            self.invoke(name, qualifier, {'case': label + '-throttle', 'kind': 'success'})
        except ClientError as error:
            require(error.response['Error']['Code'] == 'TooManyRequestsException', str(error))
            return {'runtime_marker': markers[0], 'concurrency_rejection': error.response,
                'docker': self.runtime_evidence()}
        raise AssertionError('held runtime failed to exhaust reserved concurrency')

    def release(self, label):
        self.sqs.send_message(QueueUrl=self.queues['gate']['url'], MessageBody=json.dumps({'case': label}))

    def release_held(self):
        if self.held is None:
            return None
        held, self.held = self.held, None
        self.release(held['case'])
        try:
            return held['future'].result(timeout=30)
        except ClientError as error:
            return {'error': error.response}

    def controls(self, name):
        configured = self.config(name, 'live')
        retry = self.accept('stable-retry-two', name, 'live', 'fail')
        self.report['controls']['retry'] = retry
        self.drive(retry)
        require(len(retry['runtime_markers']) == 3, 'retry control did not execute three real failures')
        require(len(retry['destinations']) == 1, 'retry control did not deliver one destination')
        context = retry['destinations'][0]['requestContext']
        require(context['condition'] == 'RetriesExhausted' and context['approximateInvokeCount'] == 3, 'retry control budget mismatch')
        retry['configured'] = configured
        age = self.accept('stable-age-240', name, 'live', 'hold_fail')
        self.report['controls']['age'] = age
        self.wait(lambda: self.receipts(age['name'], phase='entered'), 'first age-control runtime entry')
        self.advance(120)
        self.release(age['name'])
        row = self.wait(lambda: self.settled(age['request_id']), 'first real held failure')['row']
        require(row and row['state'] == 'queued', 'age control did not retain first failure')
        self.advance(60)
        self.wait(lambda: len(self.receipts(age['name'], phase='entered')) == 2, 'second age-control runtime entry')
        self.release(age['name'])
        self.drive(age)
        require(len(age['runtime_markers']) == 2 and len(age['destinations']) == 1, 'age control consumer evidence mismatch')
        context = age['destinations'][0]['requestContext']
        require(context['condition'] == 'EventAgeExceeded' and context['approximateInvokeCount'] == 2, 'age control budget mismatch')
        age['configured'] = configured
        self.report['assertions'].append('Same unchanged alias: real retry-two/count-three and age240/count-two controls, stable accepted request IDs and destination ARNs')

    def queued_case(self, label, name, qualifier, configured):
        barrier = self.hold(name, self.published[name], label + '-barrier')
        case = self.accept(label, name, qualifier)
        self.report['cases'][label] = case
        case['configured'] = configured
        case['barrier'] = barrier
        def throttled():
            row = self.row(case['request_id'])
            case['pre_dispatch_last_row'] = row
            return row if row and row['state'] == 'queued' and row['response_status'] == 429 and row['invoke_count'] == 0 else None
        case['before_deletion'] = self.wait(throttled, 'accepted event queued behind the real runtime barrier')
        require(not self.receipts(label), 'accepted target entered before deletion')
        return case

    def absent_alias(self, case):
        try:
            self.fn.get_alias(FunctionName=case['function'], Name=case['qualifier'])
        except ClientError as error:
            require(error.response['Error']['Code'] == 'ResourceNotFoundException', str(error))
            return error.response
        raise AssertionError('deleted alias still exists')

    def restart_case(self, case):
        before = self.now()
        self.controller.stop(timeout=45, kill_on_timeout=True)
        self.start()
        case['restart'] = {'before': before, 'after': self.now()}
        require(case['restart']['after'] == before, 'SQLite clock changed across restart')
        case['after_restart'] = self.row(case['request_id'])
        require(case['after_restart'] and case['after_restart']['request_id'] == case['request_id'],
            'accepted event lost at restart')

    def metric_snapshot(self, name, qualifier):
        dimensions = [{'Name': 'FunctionName', 'Value': name},
            {'Name': 'Resource', 'Value': name + (':' + qualifier if qualifier else '')}]
        result = {'service_time': self.now(), 'scope': 'Exact FunctionName+Resource; no ExecutedVersion dimension',
            'reads': {}, 'totals': {}}
        self.report.setdefault('metric_snapshots', []).append(result)
        for metric in ('AsyncEventsReceived', 'AsyncEventsDropped', 'Invocations', 'Errors', 'DestinationDeliveryFailures', 'DeadLetterErrors'):
            request = {'Namespace': 'AWS/Lambda', 'MetricName': metric, 'Dimensions': dimensions,
                'StartTime': datetime(2026, 9, 30, 12, tzinfo=timezone.utc),
                'EndTime': instant(result['service_time']) + timedelta(minutes=1),
                'Period': 60, 'Statistics': ['Sum']}
            response = self.clients['cloudwatch'].get_metric_statistics(**request)
            result['reads'][metric] = {'request': request, 'response': response}
            points = response['Datapoints']
            # Missing datapoints are retained as unmeasured, not asserted zero.
            result['totals'][metric] = sum(point['Sum'] for point in points) if points else None
        return result

    def dlq_control(self, name, qualifier, retries, destination='destination'):
        self.fn.create_alias(FunctionName=name, Name=qualifier, FunctionVersion='1')
        configured = self.config(name, qualifier, retries=retries, age=180, destination=destination)
        case = self.accept(qualifier + '-positive-failure', name, qualifier, 'fail')
        case['configured'] = configured
        case['configuration_evidence'] = '120-second local fixture application barrier plus real consumer control; SDK readback alone is not propagation proof'
        self.report['controls'][case['name']] = case
        self.drive(case)
        require(len(case['runtime_markers']) == retries + 1, 'positive failure handler count mismatch')
        require(len(case['destinations']) == (1 if destination else 0), 'positive failure OnFailure route mismatch')
        require(len(case['dlq_receipts']) == 1, 'ordinary handler failure did not reach legacy DLQ')
        receipt = case['dlq_receipts'][0]
        require(receipt['body'] == {'case': case['name'], 'kind': 'fail'}, 'legacy DLQ changed original event')
        attrs = receipt['message_attributes']
        require(attrs['RequestID']['StringValue'] == case['request_id'], 'positive DLQ request identity mismatch')
        case['runtime_identity'] = {'markers': case['runtime_markers'], 'image': self.report.get('runtime_image')}
        self.advance(60)
        return configured

    def deleted_dlq(self, name, retries, diagnostic=False, destination='destination', deny_dlq=False):
        label = 'deleted-dlq-retry' + str(retries) + ('-no-onfailure' if not destination else '') + ('-current-iam-denial' if deny_dlq else '')
        configured = self.dlq_control(name, label, retries, destination)
        before = self.metric_snapshot(name, label)
        case = self.queued_case(label, name, label, configured)
        case['metrics_before_acceptance'] = before
        if deny_dlq:
            case['iam_policy_after_acceptance'] = self.set_runtime_policy(deny_dlq=True)
            case['iam_policy_readback'] = self.iam.get_role_policy(RoleName=self.prefix, PolicyName='runtime')
            case['configuration_evidence'] = 'Policy readback is control-plane evidence; actual OnFailure delivery plus SDK DeadLetterErrors and absent DLQ establish current IAM evaluation locally'
        case['deletion'] = self.fn.delete_alias(FunctionName=name, Name=label)
        case['deleted_readback'] = self.absent_alias(case)
        case['parent_after_alias_deletion'] = self.fn.get_function_configuration(FunctionName=name)
        case['barrier_response'] = self.release_held()
        if retries:
            self.missing_lookup(case)
        self.restart_case(case)
        case['deleted_readback_after_restart'] = self.absent_alias(case)
        self.drive(case, horizon=179 if retries else 600)
        if retries:
            require(case['last_retained_row'] and case['last_retained_row']['invoke_count'] == 0,
                'retry1 deleted alias lost pending zero-handler state before age180')
            case['before_expiry'] = {'service_time': self.now(), 'row': case['last_retained_row']}
            self.drive(case, horizon=180)
            self.no_retained_work(case)
        require(not case['runtime_markers'], 'deleted alias unexpectedly entered handler')
        if not retries and destination:
            require(len(case['destinations']) == 1, 'retry0 missing actual OnFailure receipt')
            body = case['destinations'][0]
            require(body['requestContext']['condition'] == 'RetriesExhausted'
                and body['requestContext']['approximateInvokeCount'] == 1
                and body['responseContext']['statusCode'] == 404
                and 'responsePayload' not in body and 'executedVersion' not in body['responseContext'],
                'retry0 deleted alias native OnFailure shape mismatch')
        else:
            require(not case['destinations'], 'deleted alias unexpectedly delivered OnFailure')
        self.advance(60)
        self.drive(case, horizon=600)
        after = self.metric_snapshot(name, label)
        case['metrics_after'] = after
        case['metric_deltas'] = {metric: (after['totals'][metric] or 0) - (before['totals'][metric] or 0)
            for metric in before['totals']}
        case['metric_delta_scope'] = 'Difference in published SDK sums; absent datapoints contribute zero only to this arithmetic, raw absence remains unmeasured'
        if diagnostic:
            case['diagnostic'] = 'Bounded local observation; missing DLQ is not a native expected fate'
            if retries == 0:
                require(not case['dlq_receipts'] and case['metric_deltas']['DeadLetterErrors'] == 1,
                    'baseline did not reproduce retry0 absent DLQ plus SDK DeadLetterErrors')
                self.report['assertions'].append('Failed-before: retry0 absent alias produced real404/count1 OnFailure, no handler or DLQ, and one SDK DeadLetterErrors after positive legacy DLQ control')
        elif deny_dlq:
            require(not case['dlq_receipts'] and case['metric_deltas']['DeadLetterErrors'] == 1
                and case['metric_deltas']['DestinationDeliveryFailures'] == 0,
                'current IAM denial did not independently reject legacy DLQ')
            case['authority_scope'] = 'Explicit current IAM deny on exact retained DLQ after acceptance, across controller restart; native deleted-alias IAM timing is not asserted'
            self.report['assertions'].append(label + ': current IAM exact-DLQ deny gives DeadLetterErrors1 while OnFailure404 still delivers')
            case['iam_policy_restoration'] = self.set_runtime_policy()
        else:
            self.calibrate_dlq(case, retries)

    def calibrate_dlq(self, case, retries):
        native_case = 'alias-retry' + str(retries) + '-deleted-before-entry'
        captures = [row for row in self.native_dlq['messages']
            if row['queue'] == 'legacy' and row['body'].get('case') == native_case]
        if not captures:
            require(retries != 0, 'retry0 after proof requires positive native legacy DLQ capture')
            case['native_calibration'] = {'case': native_case, 'status': 'inconclusive',
                'scope': 'No native positive DLQ capture in referenced snapshot; local expiry DLQ is diagnostic only, not a native expected fate'}
            return
        require(len(captures) == 1, 'native DLQ capture is not unique')
        source = captures[0]
        accepted = next(row for row in self.native_dlq['calls'] if row.get('label') == 'admit-' + native_case)
        source_event = self.native_dlq['events'][native_case]
        source_attrs = source['message_attributes']
        require(source['body_raw'] == source_event['payload_raw'], 'native DLQ does not preserve original payload bytes')
        require(source_attrs['RequestID'] == {'DataType': 'String', 'StringValue': accepted['metadata']['RequestId']},
            'native DLQ does not preserve accepted request identity')
        source_arn = self.native_dlq['owned']['functions']['aliases']['aliases'][source_event['target']]['AliasArn']
        expected = {
            'RequestID': {'DataType': 'String', 'StringValue': case['request_id']},
            'ErrorCode': source_attrs['ErrorCode'],
            'ErrorMessage': dict(source_attrs['ErrorMessage'],
                StringValue=source_attrs['ErrorMessage']['StringValue'].replace(source_arn, case['requested_arn']))}
        case['native_calibration'] = {'case': native_case, 'status': 'positive-capture', 'receipt': source,
            'acceptance': accepted, 'expected_local_attributes': expected,
            'scope': 'Exact positive payload/accepted-ID/error projection; route independence is a local-only variant'}
        require(len(case['dlq_receipts']) == 1, 'deleted alias missing native-calibrated legacy DLQ')
        receipt = case['dlq_receipts'][0]
        require(receipt['queue'] == 'legacy-dlq', 'configured legacy DLQ target mismatch')
        require(receipt['body'] == case['payload'] and receipt['raw_body'] == case['payload_raw'],
            'deleted alias DLQ changed original event bytes')
        require(receipt['message_attributes'] == expected, 'deleted alias DLQ native exact attributes mismatch')
        require(case['metric_deltas']['DeadLetterErrors'] == 0, 'successful DLQ emitted DeadLetterErrors')
        self.report['assertions'].append(case['name'] + ': native-positive exact original bytes, accepted RequestID, ErrorCode and ErrorMessage; retained controller restart and SDK DeadLetterErrors0')

    def missing_alias_controls(self, name, qualifier):
        configured = self.config(name, qualifier, retries=1, age=180)
        retry = self.accept(qualifier + '-control-retry', name, qualifier, 'fail')
        self.report['controls'][retry['name']] = retry
        self.drive(retry)
        require(len(retry['runtime_markers']) == 2 and len(retry['destinations']) == 1,
            'retry1 control requires two real handler failures and one destination')
        context = retry['destinations'][0]['requestContext']
        require(context['condition'] == 'RetriesExhausted' and context['approximateInvokeCount'] == 2,
            'retry1 control terminal mismatch')
        age = self.accept(qualifier + '-control-age', name, qualifier, 'hold_fail')
        self.report['controls'][age['name']] = age
        self.wait(lambda: self.receipts(age['name'], phase='entered'), 'age180 held handler entry')
        self.advance(130)
        self.release(age['name'])
        self.wait(lambda: self.settled(age['request_id']), 'age180 held handler completion')
        self.drive(age)
        require(len(age['runtime_markers']) == 1 and len(age['destinations']) == 1,
            'age180 control requires one real handler failure and one destination')
        context = age['destinations'][0]['requestContext']
        require(context['condition'] == 'EventAgeExceeded' and context['approximateInvokeCount'] == 1,
            'age180 control terminal mismatch')
        retry['configured'] = age['configured'] = configured
        # Publish completed control minutes before taking an SDK-only baseline.
        self.advance(60)
        self.report['assertions'].append(qualifier + ': completed retry1/count2 and age180/count1 handler controls before mutation')
        return configured

    def missing_lookup(self, case):
        before = self.snapshot(case)
        require(before and before['state'] == 'queued', 'missing alias event is no longer queued')
        absent = self.absent_alias(case)
        self.advance(max(0, (instant(before['due']) - instant(self.now())).total_seconds()))
        def missing():
            row = self.row(case['request_id'])
            if row is None or row['state'] == 'completed':
                raise AssertionError('missing alias exhausted handler budget before age')
            return row if row['state'] == 'queued' and row['system_errors'] > before['system_errors'] \
                and row['version'] > before['version'] else None
        row = self.wait(missing, 'actual missing-alias scheduling lookup')
        case.setdefault('missing_lookups', []).append({'service_time': self.now(),
            'alias_sdk_readback': absent, 'row': row})
        require(row['invoke_count'] == 0, 'missing alias consumed handler retry budget')
        require(not self.receipts(case['name']) and not self.receipts(case['name'], 'destination'),
            'missing lookup fabricated runtime entry or destination')
        return row

    def no_retained_work(self, case):
        with sqlite3.connect(f'file:{self.database}?mode=ro', uri=True) as connection:
            invocations = connection.execute('SELECT COUNT(*) FROM lambda_invocations WHERE request_id=?',
                (case['request_id'],)).fetchone()[0]
            deliveries = connection.execute('SELECT COUNT(*) FROM lambda_outcome_deliveries WHERE invocation_id=?',
                (case['before_deletion']['id'],)).fetchone()[0]
        row = {'service_time': self.now(), 'invocations': invocations, 'outcome_deliveries': deliveries}
        case.setdefault('retained_work_checks', []).append(row)
        require(invocations == 0 and deliveries == 0, 'expired missing alias retained runnable invocation or outcome work')

    def missing_alias(self, name, recreate):
        label = 'missing-alias-' + ('recreate' if recreate else 'expire')
        self.fn.create_alias(FunctionName=name, Name=label, FunctionVersion='1')
        configured = self.missing_alias_controls(name, label)
        before = self.metric_snapshot(name, label)
        for metric, expected in (('AsyncEventsReceived', 2), ('AsyncEventsDropped', 2), ('Invocations', 3), ('Errors', 3)):
            require(before['totals'][metric] == expected, 'exact alias control metric baseline mismatch: ' + metric)
        case = self.queued_case(label, name, label, configured)
        case['metrics_before_acceptance'] = before
        case['deletion'] = self.fn.delete_alias(FunctionName=name, Name=label)
        case['deleted_readback'] = self.absent_alias(case)
        case['mutation_service_time'] = self.now()
        case['parent_after_alias_deletion'] = self.fn.get_function_configuration(FunctionName=name)
        case['barrier_response'] = self.release_held()
        self.missing_lookup(case)
        self.restart_case(case)
        case['deleted_readback_after_restart'] = self.absent_alias(case)
        require(case['after_restart']['invoke_count'] == 0
            and case['after_restart']['system_errors'] == case['missing_lookups'][-1]['row']['system_errors'],
            'SQLite restart lost zero-handler missing-alias state')
        self.missing_lookup(case)
        if recreate:
            case['replacement_service_time'] = self.now()
            require((instant(self.now()) - instant(case['accepted_service_time'])).total_seconds() < 180,
                'alias recreation happened after maximum age')
            # Alias deletion also removes its configuration. Reapply it behind a
            # real runtime barrier; a separate consumer control, not a pause or
            # API readback, proves the replacement route before old work runs.
            case['replacement_config_barrier'] = self.hold(name, self.published[name], label + '-config-barrier')
            case['replacement'] = self.fn.create_alias(FunctionName=name, Name=label, FunctionVersion='2')
            case['replacement_config'] = self.config(name, label, retries=1, age=180, apply=False)
            case['before_application'] = self.config_snapshot(name, label)
            self.advance(120)
            def held_retry():
                row = self.row(case['request_id'])
                return row if row and row['state'] == 'queued' and row['response_status'] == 429 \
                    and instant(row['due']) > instant(self.now()) else None
            case['held_through_application'] = self.wait(held_retry, 'replacement config real-barrier retry')
            require(not self.held['future'].done() and not self.receipts(label),
                'accepted event entered before replacement route application')
            case['replacement_config_barrier_response'] = self.release_held()
            control = self.route_control(label + '-replacement-route', name, label, 'destination')
            case['new_applied_settings_control'] = control
            case['after_application'] = self.config_snapshot(name, label)
            self.drive(case)
            require(len(case['runtime_markers']) == 1, 'recreated alias did not execute exactly once')
            marker = case['runtime_markers'][0]
            require(marker['deployment'] == 'replacement' and marker['function_version'] == '2',
                'recreated alias did not execute replacement deployment/version2')
            self.require_success_route(case, 'destination')
            require(case['destinations'][0]['responseContext']['executedVersion'] == '2',
                'recreated alias destination lost resolved version2')
            case['completed_age_seconds'] = (instant(case['destinations'][0]['timestamp'])
                - instant(case['accepted_service_time'])).total_seconds()
            require(case['completed_age_seconds'] < 180, 'replacement accepted event completed after original age180 deadline')
            self.advance(60)
            case['metric_delta_controls'] = [control]
            expected = {'AsyncEventsReceived': 2, 'AsyncEventsDropped': 0, 'Invocations': 2, 'Errors': 0}
            self.report['assertions'].append(label + ': two real missing lookups across SQLite restart preserve zero handler attempts, then replacement version2 Success/count1 with original accepted ID')
        else:
            self.drive(case, horizon=179)
            retained = case['last_retained_row']
            require(retained and retained['state'] == 'queued' and retained['invoke_count'] == 0
                and retained['system_errors'] > 2, 'retry1 missing alias did not remain queued without handler attempts before age180')
            require(not case['runtime_markers'] and not case['destinations'], 'missing alias produced evidence before expiry')
            case['before_expiry'] = {'service_time': self.now(), 'row': retained}
            self.drive(case, horizon=180)
            self.no_retained_work(case)
            case['bounded_absence_windows'] = []
            for horizon in (180, 240, 600):
                elapsed = (instant(self.now()) - instant(case['accepted_service_time'])).total_seconds()
                self.advance(horizon - elapsed)
                self.drive(case, horizon=horizon)
                require(not case['runtime_markers'] and not case['destinations'],
                    'expired missing alias fabricated runtime entry or destination')
                self.no_retained_work(case)
                case['bounded_absence_windows'].append({'seconds_after_acceptance': horizon,
                    'service_time': self.now(), 'runtime_markers': [], 'destinations': []})
            expected = {'AsyncEventsReceived': 1, 'AsyncEventsDropped': 1, 'Invocations': 0, 'Errors': 0}
            self.report['assertions'].append(label + ': queued through age179 without handler attempts, age180 consumes retained work, no runtime/destination through bounded local age600; not an AWS scheduling or six-hour assertion')
        after = self.metric_snapshot(name, label)
        case['metrics_after'] = after
        case['metric_deltas'] = {metric: after['totals'][metric] - before['totals'][metric] for metric in expected}
        require(case['metric_deltas'] == expected, 'missing alias exact scoped SDK metric deltas mismatch')
        self.report['assertions'].append(label + ': exact alias SDK metric deltas ' + json.dumps(expected, sort_keys=True))

    def deleted_target(self, label, name, qualifier, retries, failed_handler=False):
        configured = self.config(name, qualifier, retries=retries, age=180)
        if failed_handler:
            case = self.accept(label, name, qualifier, 'fail')
            self.report['cases'][label] = case
            case['configured'] = configured
            self.wait(lambda: self.receipts(label, phase='entered'), 'actual handler failure entry')
            def failed():
                row = self.row(case['request_id'])
                return row if row and row['state'] == 'queued' and row['invoke_count'] == 1 \
                    and row['response_status'] == 200 and row['response_error'] == 'Unhandled' else None
            case['before_deletion'] = self.wait(failed, 'retained actual runtime failure')
            require(json.loads(case['before_deletion']['response_payload'])['errorType'] == 'RuntimeError',
                'retained failure was not the actual Python runtime response')
        else:
            case = self.queued_case(label, name, qualifier, configured)
        if qualifier and not qualifier.isdecimal():
            case['deletion'] = self.fn.delete_alias(FunctionName=name, Name=qualifier)
            case['deleted_readback'] = self.absent_alias(case)
        elif qualifier:
            case['deletion'] = self.fn.delete_function(FunctionName=name, Qualifier=qualifier)
            self.require_absent(name + ':' + qualifier,
                lambda: self.fn.get_function(FunctionName=name, Qualifier=qualifier),
                ('ResourceNotFoundException',))
            case['surviving_parent'] = self.fn.get_function(FunctionName=name)['Configuration']
        else:
            case['deletion'] = self.delete_function(name)
            self.require_absent(name, lambda: self.fn.get_function(FunctionName=name),
                ('ResourceNotFoundException',))
        if not failed_handler:
            case['barrier_response'] = self.release_held()
        self.restart_case(case)
        self.drive(case)
        require(len(case['runtime_markers']) == (1 if failed_handler else 0),
            'deleted target entered a missing or different runtime')
        self.calibrate_deleted_target(case)

    def calibrate_deleted_target(self, case):
        finding = self.native_targets['findings'][case['name']]
        case['native_calibration'] = {'finding': finding,
            'scope': 'Only positive retained native records calibrate fields. Missing terminal evidence is explicitly unproven.'}
        terminals = finding['onfailure']
        if not terminals:
            case['native_calibration']['status'] = 'terminal-unproven'
            return
        require(len(terminals) == 1 and len(case['destinations']) == 1,
            'native-positive deleted target terminal delivery mismatch')
        expected, actual = terminals[0]['body'], case['destinations'][0]
        for field in ('condition', 'approximateInvokeCount'):
            require(actual['requestContext'][field] == expected['requestContext'][field],
                'deleted target native request context mismatch: ' + field)
        require(actual.get('responseContext') == expected.get('responseContext'),
            'deleted target native response context mismatch')
        require(('responsePayload' in actual) == ('responsePayload' in expected),
            'deleted target invented or lost real handler response')
        if actual.get('responsePayload'):
            require(actual['responsePayload']['errorType'] == expected['responsePayload']['errorType'],
                'deleted target changed actual handler failure type')
        native_dlq = finding['legacy_dlq']
        if native_dlq:
            require(len(native_dlq) == 1 and len(case['dlq_receipts']) == 1,
                'native-positive deleted target legacy DLQ missing')
            receipt = case['dlq_receipts'][0]
            require(receipt['raw_body'] == case['payload_raw'], 'deleted target DLQ changed accepted bytes')
            expected_arn = case['requested_arn'] + (':$LATEST' if not case['qualifier'] else '')
            expected_attrs = dict(native_dlq[0]['message_attributes'])
            expected_attrs['RequestID'] = {'DataType': 'String', 'StringValue': case['request_id']}
            expected_attrs['ErrorMessage'] = {'DataType': 'String', 'StringValue': 'Function not found: ' + expected_arn}
            require(receipt['message_attributes'] == expected_attrs, 'deleted target native DLQ error projection mismatch')
        case['native_calibration']['status'] = 'positive-terminal'
        self.report['assertions'].append(case['name'] + ': positive native terminal condition/count/status, real runtime attempt identity and SQLite restart')

    def recreation_config_reset(self):
        name = self.prefix + '-recreation-reset'
        self.create(name, 'original')
        configured = self.config(name, '', retries=1, age=240)
        case = self.queued_case('function-recreated-config-reset', name, '', configured)
        case['deletion'] = self.delete_function(name)
        case['replacement'] = self.create(name, 'replacement')
        case['pending_configuration'] = self.config(name, '', destination='replacement-destination', apply=False)
        case['before_reset'] = self.config_snapshot(name, '')
        case['configuration_deletion'] = self.fn.delete_function_event_invoke_config(FunctionName=name)
        self.require_absent(name + ':event-config',
            lambda: self.fn.get_function_event_invoke_config(FunctionName=name),
            ('ResourceNotFoundException',))
        case['barrier_response'] = self.release_held()
        self.restart_case(case)
        require(not case['after_restart']['settings_detached'],
            'explicit configuration reset revived detached accepted settings')
        self.drive(case)
        require(len(case['runtime_markers']) == 1 and not case['destination_receipts'],
            'explicit configuration deletion did not restore default destination omission')
        require(case['runtime_markers'][0]['deployment'] == 'replacement',
            'configuration deletion fenced the actual replacement runtime')
        case['evidence_scope'] = 'Local reset/application invariant; no new native recreation deletion timing claim'
        self.report['assertions'].append('Explicit pending replacement configuration deletion restores defaults across SQLite restart, never revives old destination or blocks replacement runtime')

    def lifecycle(self, label, name, qualifier, recreate=False, restart=False, retries=2,
            retarget=False, replacement_config=False, apply_before_resume=True, age=240, deny_old_destination=False):
        configured = self.config(name, qualifier, retries=retries, age=age)
        old_control = self.route_control(label + '-old-route', name, qualifier, 'destination') if replacement_config else None
        case = self.queued_case(label, name, qualifier, configured)
        if replacement_config:
            case['old_applied_settings_control'] = old_control
            case['application_phase'] = 'after-applied-control' if apply_before_resume else 'before-application-observation'
        if retarget:
            require(qualifier, 'retarget requires an alias')
            case['replacement'] = self.fn.update_alias(FunctionName=name, Name=qualifier, FunctionVersion='2')
        elif qualifier:
            case['deletion'] = self.fn.delete_alias(FunctionName=name, Name=qualifier)
            case['deleted_readback'] = self.absent_alias(case)
            if recreate:
                case['replacement'] = self.fn.create_alias(FunctionName=name, Name=qualifier, FunctionVersion='2')
        else:
            case['deletion'] = self.delete_function(name)
            try:
                self.fn.get_function(FunctionName=name)
            except ClientError as error:
                require(error.response['Error']['Code'] == 'ResourceNotFoundException', str(error))
                case['deleted_readback'] = error.response
            else:
                raise AssertionError('deleted function still exists')
            if recreate:
                case['replacement'] = self.create(name, 'replacement')
        case['mutation_service_time'] = self.now()
        if replacement_config:
            case['replacement_config'] = self.config(name, qualifier, destination='replacement-destination', apply=False)
            case['before_application'] = self.config_snapshot(name, qualifier)
            if apply_before_resume:
                self.advance(120)
                # The holder remains real customer code during propagation. Wait
                # until this event is throttled again with a future retry, leaving
                # room at frozen service time for an independent route control.
                def held_retry():
                    row = self.row(case['request_id'])
                    return row if row and row['state'] == 'queued' and row['response_status'] == 429 \
                        and instant(row['due']) > instant(self.now()) else None
                case['held_through_application'] = self.wait(held_retry, 'real barrier across config application')
                require(not self.held['future'].done(), 'runtime barrier ended during config application')
                require(not self.receipts(label), 'accepted event ran before applied-settings control')
        if deny_old_destination:
            case['current_iam_deny'] = self.set_runtime_policy(deny_destination=True)
        case['barrier_response'] = self.release_held()
        if restart:
            self.restart_case(case)
        if replacement_config and apply_before_resume:
            case['new_applied_settings_control'] = self.route_control(label + '-new-route', name, qualifier, 'replacement-destination')
            case['after_application'] = self.config_snapshot(name, qualifier)
        self.drive(case)
        if replacement_config and not apply_before_resume:
            # The native same-name replacement consumed old accepted work at the
            # old route before the separately accepted new-route control.
            case['before_application_result'] = {'runtime_markers': case['runtime_markers'],
                'destination_receipts': case['destination_receipts']}
            if not qualifier and not deny_old_destination:
                self.require_success_route(case, 'destination')
                self.report['assertions'].append(label + ': native-observed same-name replacement executes accepted payload and delivers to old destination before new-route control')
            if deny_old_destination:
                require(len(case['runtime_markers']) == 1 and not case['destination_receipts'],
                    'current IAM denial failed to block retained old destination')
                self.advance(60)
                case['current_iam_metrics'] = self.metric_snapshot(name, '')
                require(case['current_iam_metrics']['totals']['DestinationDeliveryFailures'] == 1,
                    'denied retained destination did not produce actual delivery failure metric')
                case['restored_policy'] = self.set_runtime_policy()
                self.report['assertions'].append(label + ': replacement runtime executes under current role, current exact-destination deny prevents stale accepted delivery after SQLite restart')
            self.advance(120)
            case['new_applied_settings_control'] = self.route_control(label + '-new-route', name, qualifier, 'replacement-destination')
            case['after_application'] = self.config_snapshot(name, qualifier)
        if replacement_config and qualifier:
            self.require_success_route(case, 'replacement-destination')
            self.report['assertions'].append(label + ': accepted alias event reaches replacement destination after independent applied-settings consumer control')
        if replacement_config and not qualifier and apply_before_resume:
            self.require_success_route(case, 'replacement-destination')
            self.report['assertions'].append(label + ': replacement NEW-route control precedes old accepted event NEW-route terminal; exact native propagation instant remains uncalibrated')
        if recreate or retarget:
            # Native old accepted events execute the current logical replacement.
            # Never fence an accepted payload merely because its name was recreated.
            expected_version = '2' if qualifier else '$LATEST'
            require(case['runtime_markers'], 'native-established replacement runtime did not execute the accepted event')
            require(all(marker['deployment'] == 'replacement' and marker['function_version'] == expected_version
                for marker in case['runtime_markers']), 'recreated target executed the wrong deployment/version')
            self.report['assertions'].append(label + ': native-established replacement deployment/version with original accepted identity')
        if retries == 0 and not recreate:
            require(not case['runtime_markers'] and len(case['destinations']) == 1, 'native retry-zero deletion delivery mismatch')
            destination = case['destinations'][0]
            context = destination['requestContext']
            require(context['condition'] == 'RetriesExhausted' and context['approximateInvokeCount'] == 1,
                'native retry-zero deletion count/condition mismatch')
            require(destination['responseContext']['statusCode'] == 404 and 'executedVersion' not in destination['responseContext']
                and 'responsePayload' not in destination, 'native retry-zero deletion fabricated a handler result')
            self.report['assertions'].append('Native established retry-zero deleted alias: count1/status404 without runtime entry, responsePayload or executedVersion')
        if qualifier:
            try:
                self.fn.get_alias(FunctionName=name, Name=qualifier)
            except ClientError as error:
                require(error.response['Error']['Code'] == 'ResourceNotFoundException', str(error))
                self.fn.create_alias(FunctionName=name, Name=qualifier, FunctionVersion='1')
            else:
                self.fn.update_alias(FunctionName=name, Name=qualifier, FunctionVersion='1')

    def delete_function(self, name):
        arn = self.functions[name]
        require(self.fn.list_tags(Resource=arn)['Tags'].get('SmokeOwner') == self.owner, 'function ownership mismatch')
        result = self.fn.delete_function(FunctionName=name)
        del self.functions[name]
        del self.published[name]
        return result

    def require_absent(self, resource, reader, codes):
        try:
            response = reader()
        except ClientError as error:
            require(error.response['Error']['Code'] in codes, str(error))
            self.report.setdefault('cleanup_absence', []).append({'resource': resource, 'response': error.response})
            return
        raise AssertionError('owned resource survived deletion: ' + resource + ': ' + str(response))

    def cleanup(self):
        require(json.loads((self.state / 'owner.json').read_text())['owner'] == self.owner,
            'isolated state ownership mismatch')
        errors = []
        def perform(label, action):
            try:
                action()
                self.report['cleanup'].append({'resource': label, 'deleted': True})
            except Exception as error:
                errors.append(label + ': ' + str(error))
                self.report['cleanup'].append({'resource': label, 'error': str(error)})
        if self.controller.process is not None and self.controller.process.poll() is None:
            if self.held:
                perform('held runtime release', self.release_held)
            for name in list(self.functions):
                def delete_owned_function(name=name):
                    self.delete_function(name)
                    self.require_absent(name, lambda: self.fn.get_function(FunctionName=name),
                        ('ResourceNotFoundException',))
                perform(name, delete_owned_function)
            for queue in self.queues.values():
                def delete_queue(queue=queue):
                    require(self.sqs.list_queue_tags(QueueUrl=queue['url']).get('Tags', {}).get('SmokeOwner') == self.owner,
                        'queue ownership mismatch')
                    self.sqs.delete_queue(QueueUrl=queue['url'])
                    self.require_absent(queue['arn'],
                        lambda: self.sqs.get_queue_attributes(QueueUrl=queue['url'], AttributeNames=['QueueArn']),
                        ('AWS.SimpleQueueService.NonExistentQueue', 'QueueDoesNotExist'))
                perform(queue['arn'], delete_queue)
            if self.role:
                def delete_role():
                    tags = self.iam.list_role_tags(RoleName=self.prefix)['Tags']
                    require({'Key': 'SmokeOwner', 'Value': self.owner} in tags, 'role ownership mismatch')
                    self.iam.delete_role_policy(RoleName=self.prefix, PolicyName='runtime')
                    self.iam.delete_role(RoleName=self.prefix)
                    self.require_absent(self.role, lambda: self.iam.get_role(RoleName=self.prefix), ('NoSuchEntity',))
                perform(self.role, delete_role)
        perform('owned controller', lambda: self.controller.stop(timeout=45, kill_on_timeout=True))
        def docker_clean():
            containers = self.docker('ps', '-aq', '--filter', 'label=io.stackd.lambda.instance=' + self.namespace).split()
            volumes = self.docker('volume', 'ls', '-q', '--filter', 'label=io.stackd.lambda.instance=' + self.namespace).split()
            self.report['docker_cleanup'] = {'namespace': self.namespace, 'remaining_containers': containers,
                'remaining_volumes': volumes}
            require(not containers and not volumes, 'owned Docker resources survived controller close')
        perform('exact Docker namespace ' + self.namespace, docker_clean)
        self.pool.shutdown(wait=True)
        self.report['cleanup_errors'] = errors
        self.report['state_retained_for_diagnostics'] = str(self.state)
        return errors

    def run(self):
        failure = None
        try:
            if 'deleted-dlq-after' in self.args.scenarios:
                require(self.args.native_dlq_evidence, 'after proof requires a native evidence artifact')
                evidence = Path(self.args.native_dlq_evidence).read_bytes()
                self.native_dlq = json.loads(evidence)
                self.report['native_dlq_source'] = {'path': self.args.native_dlq_evidence,
                    'sha256': hashlib.sha256(evidence).hexdigest()}
                self.report['sources'].append(self.args.native_dlq_evidence)
            if 'deleted-targets' in self.args.scenarios:
                require(self.args.native_target_evidence, 'deleted targets require retained native evidence')
                evidence = Path(self.args.native_target_evidence).read_bytes()
                self.native_targets = json.loads(evidence)
                self.report['native_target_source'] = {'path': self.args.native_target_evidence,
                    'sha256': hashlib.sha256(evidence).hexdigest()}
                self.report['sources'].append(self.args.native_target_evidence)
            self.start()
            self.setup()
            alias_name = self.prefix + '-alias'
            self.create(alias_name, 'original')
            self.fn.update_function_configuration(FunctionName=alias_name, Environment=self.environment('replacement'))
            self.ready(alias_name)
            require(self.fn.publish_version(FunctionName=alias_name)['Version'] == '2', 'different published replacement target missing')
            self.fn.create_alias(FunctionName=alias_name, Name='live', FunctionVersion='1')
            if 'deleted-dlq-before' in self.args.scenarios or 'deleted-dlq-after' in self.args.scenarios:
                diagnostic = 'deleted-dlq-before' in self.args.scenarios
                self.deleted_dlq(alias_name, 0, diagnostic=diagnostic)
                self.deleted_dlq(alias_name, 1, diagnostic=diagnostic)
                if not diagnostic:
                    self.deleted_dlq(alias_name, 0, destination=None)
                    self.deleted_dlq(alias_name, 0, deny_dlq=True)
            if 'missing-alias-before' in self.args.scenarios:
                self.lifecycle('missing-alias-before', alias_name, 'live', restart=True, retries=1, age=180)
                case = self.report['cases']['missing-alias-before']
                require(not case['runtime_markers'] and len(case['destinations']) == 1,
                    'baseline did not reproduce missing-alias fabricated destination')
                body = case['destinations'][0]
                require(body['requestContext']['condition'] == 'RetriesExhausted'
                    and body['requestContext']['approximateInvokeCount'] == 2
                    and body['responseContext']['statusCode'] == 404,
                    'baseline did not reproduce missing-alias exhausted handler budget')
                require((instant(case['observed_through_service_time']) - instant(case['accepted_service_time'])).total_seconds() < 180,
                    'baseline did not exhaust handler budget before maximum age')
                self.report['assertions'].append('Failed-before reproduction: retry1/age180 missing alias fabricated RetriesExhausted/count2/status404 before age without any handler entry')
            if 'missing-alias' in self.args.scenarios:
                self.missing_alias(alias_name, recreate=True)
            if 'missing-alias' in self.args.scenarios or 'missing-alias-expiry' in self.args.scenarios:
                self.missing_alias(alias_name, recreate=False)
            if 'preserved' in self.args.scenarios:
                self.controls(alias_name)
                self.lifecycle('alias-deleted-retry-zero', alias_name, 'live', retries=0)
                self.lifecycle('alias-configured-recreate', alias_name, 'live', recreate=True, restart=True, replacement_config=True)
                self.lifecycle('alias-configured-retarget', alias_name, 'live', retarget=True, restart=True, replacement_config=True)
                function_name = self.prefix + '-function'
                self.create(function_name, 'original')
                self.lifecycle('function-recreated', function_name, '', recreate=True, restart=True)
            if 'baseline' in self.args.scenarios:
                self.controls(alias_name)
                self.lifecycle('alias-deleted-retry-two', alias_name, 'live', restart=True)
                self.lifecycle('alias-recreated-version-two', alias_name, 'live', recreate=True, restart=True)
                self.lifecycle('alias-deleted-retry-zero', alias_name, 'live', retries=0)
                function_name = self.prefix + '-function'
                self.create(function_name, 'original')
                self.lifecycle('function-deleted-retry-two', function_name, '', restart=True)
                self.create(function_name, 'original')
                self.lifecycle('function-recreated', function_name, '', recreate=True, restart=True)
            if 'configured' in self.args.scenarios:
                self.lifecycle('alias-configured-recreate', alias_name, 'live', recreate=True, restart=True, replacement_config=True)
                self.lifecycle('alias-configured-retarget', alias_name, 'live', retarget=True, restart=True, replacement_config=True)
                for phase, apply in (('before', False), ('after', True)):
                    name = self.prefix + '-configured-function-' + phase
                    self.create(name, 'original')
                    self.lifecycle('function-configured-recreate-' + phase, name, '', recreate=True, restart=True,
                        replacement_config=True, apply_before_resume=apply)
            if 'function-recreation' in self.args.scenarios:
                name = self.prefix + '-recreation-routing'
                first = self.create(name, 'original')
                self.lifecycle('function-recreated-old-new-routes', name, '', recreate=True, restart=True,
                    replacement_config=True, apply_before_resume=False)
                require(int(self.published[name]) > int(first['Version']), 'same-name recreation reused a published version')
                self.require_absent(name + ':' + first['Version'],
                    lambda: self.fn.get_function(FunctionName=name, Qualifier=first['Version']),
                    ('ResourceNotFoundException',))
                for suffix, apply, deny in (('new-applied', True, False), ('current-iam', False, True)):
                    name = self.prefix + '-recreation-' + suffix
                    self.create(name, 'original')
                    self.lifecycle('function-recreated-' + suffix, name, '', recreate=True, restart=True,
                        replacement_config=True, apply_before_resume=apply, deny_old_destination=deny)
                self.recreation_config_reset()
            if 'deleted-targets' in self.args.scenarios:
                for kind in ('function', 'version'):
                    for retries in (0, 1):
                        label = kind + '-retry' + str(retries)
                        name = self.prefix + '-' + label
                        self.create(name, 'original')
                        self.deleted_target(label, name, self.published[name] if kind == 'version' else '', retries)
                for kind in ('function', 'version', 'alias'):
                    label = kind + '-failed'
                    name = self.prefix + '-' + label
                    self.create(name, 'original')
                    qualifier = ''
                    if kind == 'version':
                        qualifier = self.published[name]
                    elif kind == 'alias':
                        qualifier = 'failed'
                        self.fn.create_alias(FunctionName=name, Name=qualifier, FunctionVersion=self.published[name])
                    self.deleted_target(label, name, qualifier, 1, failed_handler=True)
            self.report['status'] = 'observed'
        except Exception as error:
            failure = error
            self.report['status'] = 'failed'
            self.report['error'] = type(error).__name__ + ': ' + str(error)
        finally:
            errors = self.cleanup()
            self.report['finished_at'] = datetime.now(timezone.utc).isoformat()
            if errors:
                self.report['status'] = 'failed'
            self.output.parent.mkdir(parents=True, exist_ok=True)
            with self.output.open('x') as stream:
                json.dump(self.report, stream, default=plain, indent=2)
                stream.write('\n')
        print(json.dumps({'status': self.report['status'], 'report': str(self.output),
            'cases': {name: {'deployments': [row['deployment'] for row in case.get('runtime_markers', [])],
                'destinations': [row['requestContext'] for row in case.get('destinations', [])]}
                for name, case in self.report['cases'].items()}, 'cleanup_errors': errors}), flush=True)
        if failure:
            raise failure
        require(not errors, 'exact-owned cleanup failed')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', default='bin/stackd')
    parser.add_argument('--telemetry-directory', default='bin')
    parser.add_argument('--state-directory', required=True)
    parser.add_argument('--report', required=True)
    parser.add_argument('--docker-host', default='unix:///var/run/docker.sock')
    parser.add_argument('--native-dlq-evidence', help='Positive native legacy DLQ artifact calibrating after assertions')
    parser.add_argument('--native-target-evidence', help='Retained native whole/fixed/postfailure deletion artifact')
    parser.add_argument('--scenarios', nargs='+',
        choices=('baseline', 'configured', 'missing-alias-before', 'missing-alias', 'missing-alias-expiry', 'preserved', 'deleted-dlq-before', 'deleted-dlq-after', 'function-recreation', 'deleted-targets'),
        default=['baseline', 'configured', 'missing-alias'],
        help='Select lifecycle workflows, failed-before reproduction, scoped missing-alias proof, or affected preserved controls')
    Proof(parser.parse_args()).run()


if __name__ == '__main__':
    main()
