#!/usr/bin/env python3
"""Capture IAM tag Query binding, authorization and validation on owned users."""
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
    require_account(probe_args.account)
    prefix = 'stackd-tag-inputs-' + uuid.uuid4().hex[:12]
    target, actor = prefix + '-target', prefix + '-actor'
    users, key, policy_created = [], None, False
    capture = {'source': 'Signed AWS IAM Query requests; owned target, actor, key and conditional policy',
               'retrieved_at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
               'observations': [], 'cleanup': False}

    def clear_tags():
        tags = require('iam', 'list-user-tags', {'UserName': target})['Tags']
        if tags:
            require('iam', 'untag-user', {'UserName': target, 'TagKeys': [tag['Key'] for tag in tags]})
        return tags

    def observe(case, fields, environment=None):
        clear_tags()
        result = raw_query('tag-user', dict(fields, UserName=target), environment)
        tags = clear_tags()
        row = {'case': case, 'actor': 'conditional' if environment else 'root', 'query': fields,
               'code': result['code'], 'http_status': result['http_status'], 'tags': tags}
        if result['code'] not in ('Success', 'AccessDenied'):
            row['message'] = result['message'].replace(target, '<target>').replace(actor, '<actor>')
        capture['observations'].append(row)
        print(json.dumps(row), flush=True)

    try:
        for name in [target, actor]:
            require('iam', 'create-user', {'UserName': name, 'Path': '/stackd-probes/'})
            users.append(name)
        policy = {'Version': '2012-10-17', 'Statement': [
            {'Effect': 'Allow', 'Action': 'iam:TagUser',
             'Resource': 'arn:aws:iam::' + probe_args.account + ':user/stackd-probes/' + target,
             'Condition': {'StringEquals': {'aws:RequestTag/team': 'approved'},
                           'ForAllValues:StringEquals': {'aws:TagKeys': ['team']}}}]}
        require('iam', 'put-user-policy', {'UserName': actor, 'PolicyName': 'TagInputs', 'PolicyDocument': json.dumps(policy)})
        policy_created = True
        key = require('iam', 'create-access-key', {'UserName': actor})['AccessKey']
        environment = dict(os.environ, AWS_ACCESS_KEY_ID=key['AccessKeyId'], AWS_SECRET_ACCESS_KEY=key['SecretAccessKey'])
        environment.pop('AWS_SESSION_TOKEN', None)
        environment.pop('AWS_PROFILE', None)
        control = {'UserName': target, 'Tags.member.1.Key': 'team', 'Tags.member.1.Value': 'approved'}
        deadline = time.monotonic() + 60
        while raw_query('tag-user', control, environment)['code'] != 'Success':
            if time.monotonic() >= deadline:
                raise RuntimeError('Owned conditional TagUser permission did not propagate')
            time.sleep(1)
        for identity in [None, environment]:
            for index in ['1', '2', '3', '10', '11', '49', '50', '51', '01', '+1', '0', '-1', 'one', '1.0']:
                observe('index_' + index, {f'Tags.member.{index}.Key': 'team', f'Tags.member.{index}.Value': 'approved'}, identity)
            for case, fields in [
                ('unknown_member', {'Tags.member.1.Key': 'team', 'Tags.member.1.Value': 'approved', 'Tags.member.1.Unknown': 'ignored'}),
                ('split_index_spelling', {'Tags.member.01.Key': 'team', 'Tags.member.1.Value': 'approved'}),
                ('gap_two_entries', {'Tags.member.1.Key': 'team', 'Tags.member.1.Value': 'approved', 'Tags.member.3.Key': 'other', 'Tags.member.3.Value': 'approved'}),
                ('denied_value', {'Tags.member.1.Key': 'team', 'Tags.member.1.Value': 'other'}),
                ('reserved_key', {'Tags.member.1.Key': 'aws:reserved', 'Tags.member.1.Value': 'approved'}),
                ('duplicate_key', {'Tags.member.1.Key': 'team', 'Tags.member.1.Value': 'approved', 'Tags.member.2.Key': 'team', 'Tags.member.2.Value': 'approved'}),
                ('duplicate_denied_value', {'Tags.member.1.Key': 'team', 'Tags.member.1.Value': 'other', 'Tags.member.2.Key': 'team', 'Tags.member.2.Value': 'other'}),
                ('duplicate_approved_then_denied', {'Tags.member.1.Key': 'team', 'Tags.member.1.Value': 'approved', 'Tags.member.2.Key': 'team', 'Tags.member.2.Value': 'other'}),
                ('duplicate_denied_then_approved', {'Tags.member.1.Key': 'team', 'Tags.member.1.Value': 'other', 'Tags.member.2.Key': 'team', 'Tags.member.2.Value': 'approved'}),
                ('duplicate_reserved', {'Tags.member.1.Key': 'aws:reserved', 'Tags.member.1.Value': 'approved', 'Tags.member.2.Key': 'aws:reserved', 'Tags.member.2.Value': 'approved'}),
                ('duplicate_with_denied_key', {'Tags.member.1.Key': 'team', 'Tags.member.1.Value': 'approved', 'Tags.member.2.Key': 'team', 'Tags.member.2.Value': 'approved', 'Tags.member.3.Key': 'other', 'Tags.member.3.Value': 'approved'}),
                ('duplicate_case', {'Tags.member.1.Key': 'team', 'Tags.member.1.Value': 'approved', 'Tags.member.2.Key': 'TEAM', 'Tags.member.2.Value': 'approved'}),
                ('invalid_characters', {'Tags.member.1.Key': 'team', 'Tags.member.1.Value': 'bad\nvalue'}),
                ('missing_value', {'Tags.member.1.Key': 'team'}),
                ('empty_value', {'Tags.member.1.Key': 'team', 'Tags.member.1.Value': ''}),
                ('empty_list', {'Tags': ''}),
            ]:
                observe(case, fields, identity)
    finally:
        if key:
            require('iam', 'delete-access-key', {'UserName': actor, 'AccessKeyId': key['AccessKeyId']})
        if policy_created:
            require('iam', 'delete-user-policy', {'UserName': actor, 'PolicyName': 'TagInputs'})
        for name in reversed(users):
            require('iam', 'delete-user', {'UserName': name})
        capture['cleanup'] = True
        Path('.stackd/probes/iam/tag_inputs.json').parent.mkdir(parents=True, exist_ok=True)
        Path('.stackd/probes/iam/tag_inputs.json').write_text(json.dumps(capture, indent=2) + '\n')
    print('Owned users, key and policy deleted')


if __name__ == '__main__':
    main()
