#!/usr/bin/env python3
"""Exact-owned, zero-target Command schema admission probe; review before running."""
import argparse
import copy
import json
from pathlib import Path
import secrets
import time
import boto3
from botocore.config import Config
from botocore.exceptions import ClientError
import yaml

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--account", required=True)
parser.add_argument("--output", type=Path)
args = parser.parse_args()
owner = 'stackd-ssm-schema-' + secrets.token_hex(6)
path = args.output or Path('.stackd/probes/ssm/' + owner + '.json')
path.parent.mkdir(parents=True, exist_ok=True)
data = {'owner': owner, 'sources': ['https://docs.aws.amazon.com/systems-manager/latest/userguide/documents-schemas-features.html', 'https://docs.aws.amazon.com/systems-manager/latest/userguide/documents-command-ssm-plugin-reference.html'], 'execution': 'Native zero-target admission only; no managed instances or native execution.', 'calls': [], 'cleanup': {}}
config = Config(retries={'max_attempts': 0}, connect_timeout=5, read_timeout=20)
session = boto3.Session(region_name='us-east-1')
client = session.client('ssm', config=config)
owned = []
commands = []
def save():
    path.write_text(json.dumps(data, indent=2, default=str) + '\n')
def call(label, operation, **args):
    time.sleep(1.1)  # Stay below the native document mutation rate limit.
    row = {'label': label, 'operation': operation, 'input': args}
    data['calls'].append(row)
    try:
        out = getattr(client, operation)(**args)
        out.pop('ResponseMetadata', None)
        row['output'] = out
        return out
    except ClientError as error:
        row['error'] = error.response['Error']
        return None
    finally:
        save()
def document(schema):
    inputs = {'runCommand': ['printf "%s\\n" "{{ message }}"'], 'timeoutSeconds': '{{ executionTimeout }}'}
    doc = {'schemaVersion': schema, 'description': 'owned schema admission', 'parameters': {'message': {'type': 'String', 'default': 'hello', 'allowedPattern': '^[a-z]+$', 'minChars': 2, 'maxChars': 12}, 'executionTimeout': {'type': 'String', 'default': '17'}}}
    if schema == '1.2':
        doc['runtimeConfig'] = {'aws:runShellScript': {'properties': [dict(inputs, id='shell')]}}
    else:
        doc['mainSteps'] = [{'action': 'aws:runShellScript', 'name': 'shell', 'inputs': inputs}]
    return doc
def send(label, name, **kwargs):
    out = call(label, 'send_command', DocumentName=name, Targets=[{'Key': 'tag:stackd-schema-owner', 'Values': [owner]}], TimeoutSeconds=30, **kwargs)
    if out:
        commands.append(out['Command']['CommandId'])
        assert out['Command']['TargetCount'] == 0, out
    return out
try:
    identity = session.client('sts', config=config).get_caller_identity()
    if identity['Account'] != args.account:
        raise RuntimeError('Unexpected native account')
    data['account'] = identity['Account']
    cases = []
    for schema in ('1.2', '2.0', '2.2'):
        for fmt in ('JSON', 'YAML'):
            cases.append((schema.replace('.', '') + '-' + fmt, document(schema), fmt))
    legacy = document('1.2')
    modern = document('2.0')
    def variant(label, base, change):
        doc = copy.deepcopy(base)
        change(doc)
        cases.append((label, doc, 'JSON'))
    prop = lambda d: d['runtimeConfig']['aws:runShellScript']['properties'][0]
    step = lambda d: d['mainSteps'][0]
    variant('12-no-id', legacy, lambda d: prop(d).pop('id'))
    variant('12-empty-id', legacy, lambda d: prop(d).update(id=''))
    variant('12-path-id', legacy, lambda d: prop(d).update(id='../shell'))
    variant('12-object', legacy, lambda d: d['runtimeConfig']['aws:runShellScript'].update(properties=prop(d)))
    variant('12-two-properties', legacy, lambda d: d['runtimeConfig']['aws:runShellScript']['properties'].append(dict(prop(d), id='second', timeoutSeconds='23')))
    variant('12-duplicate-id', legacy, lambda d: d['runtimeConfig']['aws:runShellScript']['properties'].append(copy.deepcopy(prop(d))))
    variant('12-empty-properties', legacy, lambda d: d['runtimeConfig']['aws:runShellScript'].update(properties=[]))
    variant('12-mainsteps', legacy, lambda d: d.update(mainSteps=modern['mainSteps']))
    variant('20-runtime', modern, lambda d: d.update(runtimeConfig=legacy['runtimeConfig']))
    variant('20-precondition', modern, lambda d: step(d).update(precondition={'StringEquals': ['platformType', 'Linux']}))
    variant('12-precondition', legacy, lambda d: d['runtimeConfig']['aws:runShellScript'].update(precondition={'StringEquals': ['platformType', 'Linux']}))
    variant('12-property-precondition', legacy, lambda d: prop(d).update(precondition={'StringEquals': ['platformType', 'Linux']}))
    variant('20-id-input', modern, lambda d: step(d)['inputs'].update(id='old'))
    variant('12-unknown-plugin', legacy, lambda d: d['runtimeConfig'].update({'aws:unknownPlugin': d['runtimeConfig'].pop('aws:runShellScript')}))
    variant('12-commands', legacy, lambda d: prop(d).update(commands=prop(d).pop('runCommand')))
    variant('12-numeric-timeout', legacy, lambda d: prop(d).update(timeoutSeconds=19))
    variant('12-env', legacy, lambda d: d['parameters']['message'].update(interpolationType='ENV_VAR'))
    variant('20-env', modern, lambda d: d['parameters']['message'].update(interpolationType='ENV_VAR'))
    for label, doc, fmt in cases:
        name = owner + '-' + label
        content = json.dumps(doc) if fmt == 'JSON' else yaml.safe_dump(doc, sort_keys=False)
        created = call(label, 'create_document', Name=name, Content=content, DocumentType='Command', DocumentFormat=fmt)
        if not created:
            continue
        owned.append(name)
        for _ in range(10):
            desc = call(label, 'describe_document', Name=name)
            if desc['Document']['Status'] == 'Active':
                break
            time.sleep(1)
        call(label, 'get_document', Name=name)
        send(label + '-default', name)
        send(label + '-timeout', name, Parameters={'message': ['custom'], 'executionTimeout': ['31']})
        if label in ('12-JSON', '20-JSON'):
            send(label + '-constraint', name, Parameters={'message': ['1']})
            send(label + '-bad-timeout', name, Parameters={'executionTimeout': ['0']})
            updated = copy.deepcopy(doc)
            updated['description'] = 'updated same schema'
            call(label + '-same-update', 'update_document', Name=name, Content=json.dumps(updated), DocumentVersion='$LATEST', DocumentFormat='JSON')
            time.sleep(1)
            migrated = document('2.2' if doc['schemaVersion'] == '1.2' else '1.2')
            call(label + '-schema-update', 'update_document', Name=name, Content=json.dumps(migrated), DocumentVersion='$LATEST', DocumentFormat='JSON')
            time.sleep(1)
            call(label + '-versions', 'list_document_versions', Name=name)
finally:
    for command in commands:
        out = call('cleanup-status', 'list_commands', CommandId=command)
        if out and out['Commands'] and out['Commands'][0]['Status'] not in ('Success', 'Failed', 'Cancelled', 'TimedOut'):
            call('cleanup-cancel', 'cancel_command', CommandId=command)
    for name in owned:
        call('cleanup-delete', 'delete_document', Name=name)
        call('cleanup-absent', 'describe_document', Name=name)
        data['cleanup'][name] = data['calls'][-1].get('error', {}).get('Code') == 'InvalidDocument'
    save()
    print(path)
    assert all(data['cleanup'].values()), data['cleanup']
