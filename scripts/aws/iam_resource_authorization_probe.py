#!/usr/bin/env python3
"""Capture IAM resource selection with grants limited to owned resource ARNs."""
import datetime
import json
import os
from pathlib import Path
import sys
import time
import uuid

sys.dont_write_bytecode = True
from iam_conditions_probe import require
from iam_last_access_probe import raw_query


def main():
    import argparse
    from aws_cli import require_account
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--account", required=True)
    probe_args = parser.parse_args()
    account = require_account(probe_args.account)['Account']
    prefix = 'stackd-resource-auth-' + uuid.uuid4().hex[:10]
    path = '/stackd-probes/' + prefix + '/'
    names = {kind: prefix + '-' + kind for kind in ['User', 'Actor', 'Group', 'Role', 'Profile', 'Policy']}
    cleanup = []
    capture = {'source': 'AWS IAM resource-scoped authorization on owned users, group, role, profile and policy',
               'retrieved_at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
               'observations': [], 'cleanup': False}
    replacements = {account: '123456789012', prefix.upper(): 'RESOURCE-AUTH', prefix: 'resource-auth'}

    def normalize(value):
        if isinstance(value, dict):
            return {key: normalize(item) for key, item in value.items()}
        if isinstance(value, str):
            for old, new in replacements.items():
                value = value.replace(old, new)
        return value

    def observe(case, action, fields, environment, phase='initial'):
        result = raw_query(action, fields, environment)
        row = {'case': case, 'operation': action, 'input': normalize(fields), 'phase': phase,
               'code': result['code'], 'http_status': result['http_status']}
        if result['code'] == 'Success':
            output = result['output']
            entity = next((output[key] for key in ['User', 'Group', 'Role', 'InstanceProfile', 'Policy'] if key in output), {})
            row['arn'] = normalize(entity.get('Arn', ''))
            row['user_name'] = normalize(output.get('UserName', ''))
        capture['observations'].append(row)
        print(json.dumps(row), flush=True)

    try:
        users = {}
        for kind in ['User', 'Actor']:
            users[kind] = require('iam', 'create-user', {'UserName': names[kind], 'Path': path})['User']
            cleanup.append(('delete-user', {'UserName': names[kind]}))
        group = require('iam', 'create-group', {'GroupName': names['Group'], 'Path': path})['Group']
        cleanup.append(('delete-group', {'GroupName': names['Group']}))
        trust = json.dumps({'Version': '2012-10-17', 'Statement': {'Effect': 'Allow', 'Action': 'sts:AssumeRole',
                           'Principal': {'AWS': 'arn:aws:iam::' + account + ':root'}}})
        role = require('iam', 'create-role', {'RoleName': names['Role'], 'Path': path, 'AssumeRolePolicyDocument': trust})['Role']
        cleanup.append(('delete-role', {'RoleName': names['Role']}))
        profile = require('iam', 'create-instance-profile', {'InstanceProfileName': names['Profile'], 'Path': path})['InstanceProfile']
        cleanup.append(('delete-instance-profile', {'InstanceProfileName': names['Profile']}))
        policy = require('iam', 'create-policy', {'PolicyName': names['Policy'], 'Path': path,
                         'PolicyDocument': '{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}}'})['Policy']
        cleanup.append(('delete-policy', {'PolicyArn': policy['Arn']}))
        keys = {}
        for kind in ['User', 'Actor']:
            keys[kind] = require('iam', 'create-access-key', {'UserName': names[kind]})['AccessKey']
            cleanup.append(('delete-access-key', {'UserName': names[kind], 'AccessKeyId': keys[kind]['AccessKeyId']}))
            replacements[keys[kind]['AccessKeyId']] = '<' + kind.lower() + '-key>'
        environment = dict(os.environ, AWS_ACCESS_KEY_ID=keys['Actor']['AccessKeyId'], AWS_SECRET_ACCESS_KEY=keys['Actor']['SecretAccessKey'])
        environment.pop('AWS_SESSION_TOKEN', None)
        environment.pop('AWS_PROFILE', None)
        statements = []
        for actions, arn in [
                (['iam:GetUser', 'iam:ListAccessKeys', 'iam:GetAccessKeyLastUsed', 'iam:GetContextKeysForPrincipalPolicy', 'iam:SimulatePrincipalPolicy'], users['User']['Arn']),
                (['iam:GetUser'], users['Actor']['Arn']),
                (['iam:GetGroup'], group['Arn']), (['iam:GetRole'], role['Arn']),
                (['iam:GetInstanceProfile'], profile['Arn']), (['iam:GetPolicy'], policy['Arn']),
                (['iam:CreateUser'], 'arn:aws:iam::' + account + ':user' + path + 'created/*')]:
            statements.append({'Effect': 'Allow', 'Action': actions, 'Resource': arn})
        require('iam', 'put-user-policy', {'UserName': names['Actor'], 'PolicyName': 'ResourceInputs',
                                         'PolicyDocument': json.dumps({'Version': '2012-10-17', 'Statement': statements})})
        cleanup.append(('delete-user-policy', {'UserName': names['Actor'], 'PolicyName': 'ResourceInputs'}))
        controls = [('get-user', {'UserName': names['User']}), ('get-group', {'GroupName': names['Group']}),
                    ('get-role', {'RoleName': names['Role']}), ('get-instance-profile', {'InstanceProfileName': names['Profile']}),
                    ('get-policy', {'PolicyArn': policy['Arn']}), ('get-access-key-last-used', {'AccessKeyId': keys['User']['AccessKeyId']})]
        deadline = time.monotonic() + 60
        for action, fields in controls:
            while raw_query(action, fields, environment)['code'] != 'Success':
                if time.monotonic() >= deadline:
                    raise RuntimeError('Owned resource permission did not propagate: ' + action)
                time.sleep(1)
        for action, fields in controls[:4]:
            field, value = next(iter(fields.items()))
            observe('canonical', action, fields, environment)
            observe('uppercase_name', action, {field: value.upper()}, environment)
            observe('ignored_path', action, dict(fields, Path='/unrelated/'), environment)
        observe('implicit_actor', 'get-user', {}, environment)
        observe('canonical', 'get-policy', {'PolicyArn': policy['Arn']}, environment)
        observe('key_owner', 'get-access-key-last-used', {'AccessKeyId': keys['User']['AccessKeyId']}, environment)
        observe('ignored_user_name', 'get-access-key-last-used', {'AccessKeyId': keys['User']['AccessKeyId'], 'UserName': names['Actor']}, environment)
        for action in ['get-context-keys-for-principal-policy', 'simulate-principal-policy']:
            extra = {} if action.startswith('get-') else {'ActionNames.member.1': 's3:GetObject'}
            for case, arn in [('canonical', users['User']['Arn']),
                              ('wrong_path', 'arn:aws:iam::' + account + ':user/elsewhere/' + names['User'])]:
                observe(case, action, dict(extra, PolicySourceArn=arn), environment)
        for case, requested_path in [('denied_path', path + 'blocked/'), ('allowed_path', path + 'created/')]:
            new_name = prefix + '-' + case
            observe(case, 'create-user', {'UserName': new_name, 'Path': requested_path}, environment)
            if capture['observations'][-1]['code'] == 'Success':
                cleanup.append(('delete-user', {'UserName': new_name}))
        new_path = path + 'moved/'
        require('iam', 'update-user', {'UserName': names['User'], 'NewPath': new_path})
        deadline = time.monotonic() + 60
        while raw_query('get-user', {'UserName': names['User']}, environment)['code'] != 'AccessDenied':
            if time.monotonic() >= deadline:
                raise RuntimeError('Owned moved user permission did not converge')
            time.sleep(1)
        observe('moved_user', 'get-user', {'UserName': names['User']}, environment, 'moved')
        observe('moved_key_owner', 'get-access-key-last-used', {'AccessKeyId': keys['User']['AccessKeyId']}, environment, 'moved')
    finally:
        for action, fields in reversed(cleanup):
            require('iam', action, fields)
        capture['cleanup'] = True
        Path('.stackd/probes/iam/resource_authorization.json').parent.mkdir(parents=True, exist_ok=True)
        Path('.stackd/probes/iam/resource_authorization.json').write_text(json.dumps(capture, indent=2) + '\n')
    print('Owned users, keys, policies, group, role and profile deleted')


if __name__ == '__main__':
    main()
