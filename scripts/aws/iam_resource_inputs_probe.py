#!/usr/bin/env python3
"""Capture role updates, provider tagging and access-key status on owned IAM resources."""
import datetime
import json
from pathlib import Path
import uuid

from iam_conditions_probe import call, require


def main():
    import argparse
    from aws_cli import require_account
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--account", required=True)
    probe_args = parser.parse_args()
    identity = require_account(probe_args.account)
    prefix = 'stackd-resource-inputs-' + uuid.uuid4().hex[:12]
    capture = {'source': 'AWS IAM role, access-key and federation tag APIs',
               'retrieved_at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
               'region': 'us-east-1',
               'scope': 'Owned roles, unprivileged user/key and federation providers; secret key remains in memory.',
               'documentation': [
                   'https://docs.aws.amazon.com/IAM/latest/APIReference/API_CreateRole.html',
                   'https://docs.aws.amazon.com/IAM/latest/APIReference/API_UpdateRole.html',
                   'https://docs.aws.amazon.com/IAM/latest/APIReference/API_UpdateRoleDescription.html',
                   'https://docs.aws.amazon.com/IAM/latest/APIReference/API_UpdateAccessKey.html',
                   'https://docs.aws.amazon.com/IAM/latest/APIReference/API_UntagOpenIDConnectProvider.html'],
               'creates': [], 'duration_creates': [], 'updates': [], 'tags': [], 'key_statuses': [], 'cleanup': False}
    trust = json.dumps({'Version': '2012-10-17', 'Statement': [{
        'Effect': 'Allow', 'Action': 'sts:AssumeRole',
        'Principal': {'AWS': 'arn:aws:iam::' + identity['Account'] + ':root'}}]})
    cleanup = []

    def record(section, row):
        capture[section].append(row)
        # Description payloads are in the fixture; progress only needs the case and outcome.
        print(json.dumps({'section': section, 'case': len(capture[section]), 'code': row['code']}), flush=True)

    def role_state(name):
        role = require('iam', 'get-role', {'RoleName': name})['Role']
        return {'description': role.get('Description', ''), 'duration': role['MaxSessionDuration']}

    try:
        for i, (character, count) in enumerate([('x', 1000), ('x', 1001), ('é', 500), ('é', 1000), ('é', 1001), ('', 0)]):
            name = prefix + '-' + str(i)
            code, _ = call('iam', 'create-role', {'RoleName': name, 'AssumeRolePolicyDocument': trust,
                                                'Description': character * count})
            row = {'character': character, 'count': count, 'code': code}
            if code == 'Success':
                cleanup.append(('delete-role', {'RoleName': name}))
                row['state'] = role_state(name)
            record('creates', row)

        for duration in [-1, 0, 1, 3599, 43201]:
            name = prefix + '-duration-' + str(duration)
            code, _ = call('iam', 'create-role', {'RoleName': name, 'AssumeRolePolicyDocument': trust,
                                                'MaxSessionDuration': duration})
            if code == 'Success':
                cleanup.append(('delete-role', {'RoleName': name}))
            record('duration_creates', {'duration': duration, 'code': code})

        name = prefix + '-update'
        require('iam', 'create-role', {'RoleName': name, 'AssumeRolePolicyDocument': trust,
                                      'Description': 'initial', 'MaxSessionDuration': 7200})
        cleanup.append(('delete-role', {'RoleName': name}))
        for operation, parameters in [
                ('update-role', {'Description': 'changed'}),
                ('update-role', {}),
                ('update-role', {'Description': ''}),
                ('update-role', {'Description': 'é' * 1000}),
                ('update-role', {'Description': 'é' * 1001}),
                ('update-role', {'Description': 'rejected-duration', 'MaxSessionDuration': 3599}),
                ('update-role', {'Description': 'rejected-duration', 'MaxSessionDuration': 43201}),
                ('update-role', {'MaxSessionDuration': 43200}),
                ('update-role-description', {'Description': 'é' * 1000}),
                ('update-role-description', {'Description': 'é' * 1001}),
                ('update-role-description', {'Description': ''}),
                ('update-role', {'Description': 'rejected-duration', 'MaxSessionDuration': -1}),
                ('update-role', {'Description': 'rejected-duration', 'MaxSessionDuration': 0}),
                ('update-role', {'Description': 'rejected-duration', 'MaxSessionDuration': 1})]:
            code, _ = call('iam', operation, dict(parameters, RoleName=name))
            record('updates', {'operation': operation, 'input': parameters, 'code': code, 'state': role_state(name)})

        user = prefix + '-key'
        require('iam', 'create-user', {'UserName': user})
        cleanup.append(('delete-user', {'UserName': user}))
        key = require('iam', 'create-access-key', {'UserName': user})['AccessKey']['AccessKeyId']
        cleanup.append(('delete-access-key', {'UserName': user, 'AccessKeyId': key}))
        for status in ['Expired', 'Inactive', 'Expired', 'Active']:
            code, _ = call('iam', 'update-access-key', {'UserName': user, 'AccessKeyId': key, 'Status': status})
            keys = require('iam', 'list-access-keys', {'UserName': user})['AccessKeyMetadata']
            record('key_statuses', {'status': status, 'code': code, 'stored_status': keys[0]['Status']})

        for kind in ['open-id-connect', 'saml']:
            if kind == 'open-id-connect':
                field = 'OpenIDConnectProviderArn'
                parameters = {'Url': 'https://' + prefix + '.example.com/path/', 'ThumbprintList': ['a' * 40]}
            else:
                field = 'SAMLProviderArn'
                parameters = {'Name': prefix, 'SAMLMetadataDocument': Path('internal/services/iam/testdata/federation/metadata.xml').read_text()}
            arn = require('iam', 'create-' + kind + '-provider', parameters)[field]
            cleanup.append(('delete-' + kind + '-provider', {field: arn}))
            for action, parameters in [
                    ('tag', {'Tags': [{'Key': 'Team', 'Value': 'first'}, {'Key': 'team', 'Value': 'second'}]}),
                    ('tag', {'Tags': []}),
                    ('untag', {'TagKeys': []}),
                    ('untag', {'TagKeys': ['TEAM']}),
                    ('tag', {'Tags': [{'Key': 'team', 'Value': 'updated'}]}),
                    ('untag', {'TagKeys': ['Team']})]:
                operation = action + '-' + kind + '-provider'
                code, _ = call('iam', operation, dict(parameters, **{field: arn}))
                tags = require('iam', 'list-' + kind + '-provider-tags', {field: arn})['Tags']
                record('tags', {'kind': kind, 'action': action, 'input': parameters, 'code': code,
                                'stored_tags': sorted(tags, key=lambda tag: tag['Key'])})
    finally:
        for operation, parameters in reversed(cleanup):
            require('iam', operation, parameters)
        capture['cleanup'] = True
        Path('.stackd/probes/iam/resource_inputs.json').parent.mkdir(parents=True, exist_ok=True)
        Path('.stackd/probes/iam/resource_inputs.json').write_text(json.dumps(capture, indent=2, ensure_ascii=False) + '\n')
    print('Owned roles, user/key and providers deleted')


if __name__ == '__main__':
    main()
