#!/usr/bin/env python3
"""Capture role-template resource-account conditions using owned STS sessions."""
import datetime
import json
import os
from pathlib import Path
import sys
import time
import uuid

sys.dont_write_bytecode = True
from iam_conditions_probe import require, call
from iam_last_access_probe import raw_query


def main():
    import argparse
    from aws_cli import require_account
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--account", required=True)
    probe_args = parser.parse_args()
    account = require_account(probe_args.account)['Account']
    prefix = 'stackd-template-account-' + uuid.uuid4().hex[:10]
    template = 'arn:aws:iam::aws:role-template/iam.amazonaws.com/PowerUserRoleTemplate:1'
    target = prefix + '-target'
    target_arn = 'arn:aws:iam::' + account + ':role/' + target
    power = 'arn:aws:iam::aws:policy/PowerUserAccess'
    cleanup = []
    target_created = False
    capture = {'source': 'AWS IAM role-template authorization using session-policy conditions',
               'retrieved_at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
               'observations': [], 'cleanup': False}
    downstream = {'Effect': 'Allow', 'Action': ['iam:GetRole', 'iam:CreateRole', 'iam:AttachRolePolicy'],
                  'Resource': target_arn, 'Condition': {'StringEquals': {'aws:ResourceAccount': account}}}

    def session(condition):
        grant = {'Effect': 'Allow', 'Action': 'iam:GetRoleTemplateVersion', 'Resource': '*'}
        if condition:
            grant['Condition'] = condition
        document = json.dumps({'Version': '2012-10-17', 'Statement': [grant, downstream]})
        code, result = call('sts', 'assume-role', {'RoleArn': role['Arn'], 'RoleSessionName': 'template-account', 'DurationSeconds': 900, 'Policy': document})
        if code != 'Success':
            return code, None
        credentials = result['Credentials']
        environment = dict(os.environ, AWS_ACCESS_KEY_ID=credentials['AccessKeyId'],
                           AWS_SECRET_ACCESS_KEY=credentials['SecretAccessKey'], AWS_SESSION_TOKEN=credentials['SessionToken'])
        environment.pop('AWS_PROFILE', None)
        return code, environment

    def observe(case, condition, arn=template, acquire=False, minor=None):
        nonlocal target_created
        code, environment = session(condition)
        if code != 'Success':
            raise RuntimeError('Unable to obtain owned session: ' + code)
        action = 'acquire-role' if acquire else 'get-role-template-version'
        fields = {'TemplateArn': arn}
        if minor is not None:
            fields['MinorVersion'] = minor
        if acquire:
            # Query maps have entry/key/value fields, unlike list structures.
            fields.update({'ReplacementValues.entry.1.key': 'RoleName', 'ReplacementValues.entry.1.value.Values.member.1': target,
                           'ReplacementValues.entry.2.key': 'AWSServiceName', 'ReplacementValues.entry.2.value.Values.member.1': 'lambda.amazonaws.com'})
        result = raw_query(action, fields, environment)
        row = {'case': case, 'condition': condition, 'template_arn': arn, 'acquire': acquire,
               'code': result['code'], 'http_status': result['http_status']}
        if minor is not None:
            row['requested_minor'] = minor
        if result['code'] == 'Success':
            if acquire:
                if not target_created:
                    cleanup.append(('delete-role', {'RoleName': target}))
                    cleanup.append(('detach-role-policy', {'RoleName': target, 'PolicyArn': power}))
                    target_created = True
                row['role_name'] = '<target>'
            else:
                row['minor_version'] = int(result['output']['RoleTemplateVersion']['MinorVersion'])
        capture['observations'].append(row)
        print(json.dumps(row), flush=True)

    try:
        trust = json.dumps({'Version': '2012-10-17', 'Statement': {'Effect': 'Allow', 'Action': 'sts:AssumeRole',
                           'Principal': {'AWS': 'arn:aws:iam::' + account + ':root'}}})
        role = require('iam', 'create-role', {'RoleName': prefix, 'AssumeRolePolicyDocument': trust})['Role']
        cleanup.append(('delete-role', {'RoleName': prefix}))
        policy = {'Version': '2012-10-17', 'Statement': [
            {'Effect': 'Allow', 'Action': 'iam:GetRoleTemplateVersion', 'Resource': '*'}, downstream]}
        require('iam', 'put-role-policy', {'RoleName': prefix, 'PolicyName': 'TemplateAccount', 'PolicyDocument': json.dumps(policy)})
        cleanup.append(('delete-role-policy', {'RoleName': prefix, 'PolicyName': 'TemplateAccount'}))
        deadline = time.monotonic() + 60
        while True:
            code, environment = session({})
            if code == 'Success' and raw_query('get-role-template-version', {'TemplateArn': template}, environment)['code'] == 'Success':
                break
            if time.monotonic() >= deadline:
                raise RuntimeError('Owned template-read permission did not propagate')
            time.sleep(1)
        for name, condition in [
            ('unconditional', {}), ('alias', {'StringEquals': {'aws:ResourceAccount': 'aws'}}),
            ('caller_account', {'StringEquals': {'aws:ResourceAccount': account}}),
            ('managed_policy_account', {'StringEquals': {'aws:ResourceAccount': '639982225848'}}),
            ('present', {'Null': {'aws:ResourceAccount': 'false'}}),
            ('absent', {'Null': {'aws:ResourceAccount': 'true'}}),
            ('twelve_characters', {'StringLike': {'aws:ResourceAccount': '????????????'}}),
        ]:
            observe(name, condition)
            if name in ('unconditional', 'alias', 'caller_account', 'managed_policy_account'):
                observe(name, condition, acquire=True)
        matching = {'StringEquals': {'aws:ResourceAccount': '639982225848'}}
        alias = {'StringEquals': {'aws:ResourceAccount': 'aws'}}
        catalogue = json.loads(Path('internal/iam/roletemplates/data/aws.json').read_text())
        for entry in catalogue['templates']:
            arn = entry['TemplateArn']
            if arn != template:
                observe('other_template_account', matching, arn=arn)
                observe('other_template_alias', alias, arn=arn)
        observe('missing_minor_account', matching, minor=1)
        observe('missing_minor_alias', alias, minor=1)
        observe('missing_major_account', matching, arn=template[:-1]+'2')
        observe('missing_major_alias', alias, arn=template[:-1]+'2')
    finally:
        for action, fields in reversed(cleanup):
            require('iam', action, fields)
        capture['cleanup'] = True
        # The caller account is a variable in the replay, not the observed AWS owner.
        payload = json.dumps(capture, indent=2).replace(account, '<caller-account>')
        Path('.stackd/probes/iam/template_account.json').parent.mkdir(parents=True, exist_ok=True)
        Path('.stackd/probes/iam/template_account.json').write_text(payload + '\n')
    print('Owned probe/target roles and policies deleted')


if __name__ == '__main__':
    main()
