#!/usr/bin/env python3
"""Observe function-level DLQ ownership separately from published API readback.

Uses actual Python 3.12 containers, signed local SDK calls, and retained SQLite.
Baseline mode records qualified delivery without prescribing its target. After mode
requires an explicit expectation and positive native evidence. Optional queued
coverage updates the root while an accepted alias event waits behind a real slot.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path

from lambda_async_deletion_smoke import Proof, plain, require


class OwnershipProof(Proof):
    def __init__(self, args):
        super().__init__(args)
        self.report.update({
            'scenario': 'lambda-function-level-dlq-ownership',
            'mode': args.mode,
            'evidence_scope': 'Local executable observations. API readbacks are retained separately from actual SQS delivery. Only explicit native positive captures calibrate qualified and queued target expectations; this does not measure deletion timing or AWS propagation duration.',
            'sources': ['https://docs.aws.amazon.com/lambda/latest/dg/invocation-async-retain-records.html',
                'https://docs.aws.amazon.com/lambda/latest/dg/configuration-versions.html'],
            'readbacks': {}, 'updates': [], 'restarts': [],
        })
        self.targets = {'dlq-a': 'legacy-dlq', 'dlq-b': 'replacement-dlq', 'dlq-c': 'queued-update-dlq'}

    def setup(self):
        super().setup()
        for kind in (('replacement-dlq', 'queued-update-dlq') if self.args.queued_update else ('replacement-dlq',)):
            name = self.prefix + '-' + kind
            url = self.sqs.create_queue(QueueName=name, tags={'SmokeOwner': self.owner})['QueueUrl']
            arn = self.sqs.get_queue_attributes(QueueUrl=url, AttributeNames=['QueueArn'])['Attributes']['QueueArn']
            self.queues[kind] = {'url': url, 'arn': arn, 'name': name}
        self.set_runtime_policy()
        self.report['queues'] = self.queues

    def collect(self):
        for kind, queue in self.queues.items():
            if kind == 'gate':
                continue
            for message in self.sqs.receive_message(QueueUrl=queue['url'], MaxNumberOfMessages=10,
                    WaitTimeSeconds=0, MessageAttributeNames=['All'],
                    MessageSystemAttributeNames=['All']).get('Messages', []):
                self.report['receipts'].append({'queue': kind, 'service_time': self.now(),
                    'observed_at': datetime.now(timezone.utc).isoformat(),
                    'message_id': message['MessageId'], 'body': json.loads(message['Body']),
                    'raw_body': message['Body'], 'message_attributes': message.get('MessageAttributes', {}),
                    'system_attributes': message.get('Attributes', {})})
                self.sqs.delete_message(QueueUrl=queue['url'], ReceiptHandle=message['ReceiptHandle'])

    def configure(self, name, qualifier):
        request = {'FunctionName': name, 'MaximumRetryAttempts': 0, 'MaximumEventAgeInSeconds': 600,
            'DestinationConfig': {'OnFailure': {'Destination': self.queues['destination']['arn']}}}
        if qualifier:
            request['Qualifier'] = qualifier
        return {'request': request, 'response': self.fn.put_function_event_invoke_config(**request)}

    def readbacks(self, label, name):
        result = {'service_time': self.now(), 'get_function_configuration': {},
            'get_function': {}, 'event_invoke_configuration': {}}
        for qualifier in ('', '1', 'live'):
            request = {'FunctionName': name}
            if qualifier:
                request['Qualifier'] = qualifier
            key = qualifier or '$LATEST'
            result['get_function_configuration'][key] = self.fn.get_function_configuration(**request)
            result['get_function'][key] = self.fn.get_function(**request)
            result['event_invoke_configuration'][key] = self.fn.get_function_event_invoke_config(**request)
        result['list_versions_by_function'] = self.fn.list_versions_by_function(FunctionName=name)
        result['get_alias'] = self.fn.get_alias(FunctionName=name, Name='live')
        self.report['readbacks'][label] = result
        for api in ('get_function_configuration', 'get_function'):
            for qualifier, row in result[api].items():
                configuration = row['Configuration'] if api == 'get_function' else row
                require(configuration['Environment']['Variables']['DEPLOYMENT'] ==
                    ('latest' if qualifier == '$LATEST' else 'published'), 'immutable environment identity changed')
                require(configuration['Version'] == ('$LATEST' if qualifier == '$LATEST' else '1'),
                    'published runtime version identity changed in API')
        return result

    def update_root(self, name, target):
        request = {'FunctionName': name, 'DeadLetterConfig': {'TargetArn': self.queues[self.targets[target]]['arn']}}
        result = {'request': request, 'response': self.fn.update_function_configuration(**request)}
        self.report['updates'].append(result)
        self.ready(name)
        return result

    def failure(self, label, name, qualifier, expected=None, case=None):
        if case is None:
            case = self.accept(label, name, qualifier, kind='fail')
            self.report['cases'][label] = case
        self.drive(case)
        case['dlq_receipts'] = [row for row in self.report['receipts']
            if row['queue'] in self.targets.values() and row['body'].get('case') == label]
        require(len(case['runtime_markers']) == 1, 'retry-zero failure did not execute exactly once')
        marker = case['runtime_markers'][0]
        require(marker['function_version'] == ('1' if qualifier else '$LATEST'), 'actual runtime version changed')
        require(marker['deployment'] == ('published' if qualifier else 'latest'), 'actual immutable environment changed')
        require(len(case['destination_receipts']) == 1, 'independent OnFailure receipt missing')
        destination = case['destination_receipts'][0]
        require(destination['queue'] == 'destination', 'independent OnFailure target changed')
        body = destination['body']
        require(body['requestPayload'] == case['payload'], 'OnFailure changed event payload')
        require(body['requestContext']['condition'] == 'RetriesExhausted' and
            body['requestContext']['approximateInvokeCount'] == 1 and
            body['responseContext']['statusCode'] == 200 and
            body['responseContext']['functionError'] == 'Unhandled' and
            body['responseContext']['executedVersion'] == marker['function_version'],
            'OnFailure retry-zero runtime failure projection changed')
        require(len(case['dlq_receipts']) == 1, 'ordinary failure did not reach exactly one legacy DLQ')
        receipt = case['dlq_receipts'][0]
        require(receipt['raw_body'] == case['payload_raw'], 'legacy DLQ changed original event bytes')
        require(receipt['message_attributes']['RequestID']['StringValue'] == case['request_id'],
            'legacy DLQ lost accepted request identity')
        case['observed_dlq'] = next(key for key, value in self.targets.items() if value == receipt['queue'])
        case['expected_dlq'] = expected
        if expected:
            require(case['observed_dlq'] == expected, 'actual DLQ target differs: ' + label + ': ' + case['observed_dlq'])
        return case

    def restart(self, case=None):
        before = self.now()
        self.controller.stop(timeout=45, kill_on_timeout=True)
        containers = self.docker('ps', '-aq', '--filter', 'label=io.stackd.lambda.instance=' + self.namespace).split()
        volumes = self.docker('volume', 'ls', '-q', '--filter', 'label=io.stackd.lambda.instance=' + self.namespace).split()
        require(not containers and not volumes, 'owned Docker resources survived retained restart shutdown')
        self.start()
        result = {'before_service_time': before, 'after_service_time': self.now(),
            'shutdown_containers': containers, 'shutdown_volumes': volumes}
        self.report['restarts'].append(result)
        require(before == result['after_service_time'], 'retained clock changed across restart')
        if case:
            result['request_id'] = case['request_id']
            case['after_restart'] = self.row(case['request_id'])
            require(case['after_restart'] and case['after_restart']['request_id'] == case['request_id'],
                'accepted request lost at retained restart')
            require(case['after_restart']['payload'] == case['before_update']['payload'],
                'queued payload changed across retained restart')

    def queued_update(self, name):
        self.failure('queued-latest-b-control', name, '', 'dlq-b')
        label = 'accepted-alias-root-update'
        barrier = self.hold(name, '1', label + '-barrier')
        case = self.accept(label, name, 'live', kind='fail')
        self.report['cases'][label] = case
        case['barrier'] = barrier
        def queued():
            row = self.row(case['request_id'])
            return row if row and row['state'] == 'queued' and row['response_status'] == 429 and row['invoke_count'] == 0 else None
        case['before_update'] = self.wait(queued, 'accepted alias event waiting behind actual occupied slot')
        require(not self.receipts(label), 'accepted alias entered before occupied-slot root update')
        case['root_update'] = self.update_root(name, 'dlq-c')
        self.readbacks('queued-root-update', name)
        case['barrier_response'] = self.release_held()
        self.restart(case)
        self.failure(label, name, 'live', self.args.queued_expected_dlq, case=case)
        self.failure('queued-latest-c-control', name, '', 'dlq-c')

    def run(self):
        failure = None
        try:
            if self.args.mode == 'after':
                require(self.args.native_evidence and self.args.expected_qualified_dlq,
                    'after requires positive native evidence and explicit qualified target expectation')
            if self.args.native_evidence:
                evidence = Path(self.args.native_evidence).read_bytes()
                json.loads(evidence)
                self.report['native_evidence'] = {'path': self.args.native_evidence,
                    'sha256': hashlib.sha256(evidence).hexdigest()}
                self.report['sources'].append(self.args.native_evidence)
            if self.args.mode == 'after' and self.args.queued_update:
                require(self.args.queued_expected_dlq, 'queued after proof requires positive native target expectation')
            self.start()
            self.setup()
            name = self.prefix + '-ownership'
            self.create(name, 'published')
            self.fn.update_function_configuration(FunctionName=name, Environment=self.environment('latest'))
            self.ready(name)
            self.fn.create_alias(FunctionName=name, Name='live', FunctionVersion='1')
            self.report['invoke_configurations'] = [self.configure(name, qualifier) for qualifier in ('', '1', 'live')]
            self.advance(120)
            self.report['runtime_control'] = self.hold(name, '1', 'official-runtime-control')
            self.report['runtime_control']['response'] = self.release_held()
            self.readbacks('before-root-update', name)
            for qualifier, key in (('', 'latest'), ('1', 'version1'), ('live', 'alias')):
                self.failure('initial-' + key, name, qualifier, 'dlq-a')
            self.update_root(name, 'dlq-b')
            self.readbacks('after-root-update', name)
            self.failure('updated-latest-control', name, '', 'dlq-b')
            self.restart()
            self.readbacks('after-retained-restart', name)
            for qualifier, key in (('1', 'version1'), ('live', 'alias')):
                self.failure('updated-' + key, name, qualifier, self.args.expected_qualified_dlq)
            if self.args.queued_update:
                self.queued_update(name)
            self.report['assertions'].append('Actual retry-zero failures preserve accepted request IDs and DLQ bytes, independent OnFailure, immutable runtime version/environment, and retained controller restart')
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
            'routes': {name: case.get('observed_dlq') for name, case in self.report['cases'].items()},
            'controller_exits': [run.get('exit') for run in self.controller.runs],
            'cleanup_errors': errors}), flush=True)
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
    parser.add_argument('--mode', choices=('baseline', 'after'), default='baseline')
    parser.add_argument('--native-evidence')
    parser.add_argument('--expected-qualified-dlq', choices=('dlq-a', 'dlq-b'))
    parser.add_argument('--queued-update', action='store_true')
    parser.add_argument('--queued-expected-dlq', choices=('dlq-a', 'dlq-b', 'dlq-c'))
    OwnershipProof(parser.parse_args()).run()


if __name__ == '__main__':
    main()
