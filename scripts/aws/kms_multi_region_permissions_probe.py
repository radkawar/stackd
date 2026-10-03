#!/usr/bin/env python3
"""Capture MRK creation with an existing service role and denied IAM creation."""
import datetime
import json
import os
import pathlib
import time

from aws_cli import AWSCLIError, call


def main():
    import argparse
    from aws_cli import require_account
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--account", required=True)
    probe_args = parser.parse_args()
    os.environ.setdefault('AWS_DEFAULT_REGION', 'us-east-1')
    account = require_account(probe_args.account)['Account']
    # This probe requires the role created by kms_multi_region_probe.py.
    role = 'AWSServiceRoleForKeyManagementServiceMultiRegionKeys'
    call('iam', 'get-role', {'RoleName': role})
    path = pathlib.Path(__file__).resolve().parents[2] / '.stackd/probes/kms/multi_region_permissions.json'
    fixture = {'observed_at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
               'source': 'Owned IAM user and KMS multi-Region key; pre-existing KMS service role',
               'observations': [], 'cleanup': [], 'capture_complete': False}
    name = 'stackd-mrk-permission-' + str(time.time_ns())
    user_created, access, key = False, None, None
    replacements = {account: '111111111111', name: 'stackd-mrk-permission-user'}

    def save():
        body = json.dumps(fixture, indent=2)
        for actual, normalized in replacements.items():
            body = body.replace(actual, normalized)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body + '\n')

    try:
        call('iam', 'create-user', {'UserName': name})
        user_created = True
        policy = {'Version': '2012-10-17', 'Statement': [
            {'Effect': 'Allow', 'Action': 'kms:CreateKey', 'Resource': '*'},
            {'Effect': 'Deny', 'Action': 'iam:CreateServiceLinkedRole', 'Resource': '*'}]}
        call('iam', 'put-user-policy', {'UserName': name, 'PolicyName': 'probe', 'PolicyDocument': json.dumps(policy)})
        access = call('iam', 'create-access-key', {'UserName': name})['AccessKey']
        env = dict(os.environ, AWS_ACCESS_KEY_ID=access['AccessKeyId'], AWS_SECRET_ACCESS_KEY=access['SecretAccessKey'])
        env.pop('AWS_SESSION_TOKEN', None)
        # Wait only on credential/IAM propagation; do not create duplicate keys.
        for attempt in range(30):
            try:
                out = call('kms', 'create-key', {'MultiRegion': True}, env, error_format='json')
                key = out['KeyMetadata']['KeyId']
                replacements[key] = 'mrk-00000000000000000000000000000002'
                fixture['observations'].append({'case': 'existing_role_iam_creation_denied', 'code': 'Success', 'output': out})
                break
            except AWSCLIError as error:
                parsed = error.details
                fixture['observations'].append({'case': 'existing_role_iam_creation_denied', 'code': parsed['Code'], 'error': parsed})
                save()
                if parsed['Code'] not in ['AccessDeniedException', 'UnrecognizedClientException']:
                    raise
                time.sleep(2)
        if key is None:
            raise RuntimeError('Native creation never succeeded; inspect captured denials')
        fixture['capture_complete'] = True
    finally:
        if key:
            out = call('kms', 'schedule-key-deletion', {'KeyId': key, 'PendingWindowInDays': 7})
            fixture['cleanup'].append(out)
        if access:
            call('iam', 'delete-access-key', {'UserName': name, 'AccessKeyId': access['AccessKeyId']})
        if user_created:
            call('iam', 'delete-user-policy', {'UserName': name, 'PolicyName': 'probe'})
            call('iam', 'delete-user', {'UserName': name})
            fixture['cleanup'].append({'user_deleted': name})
        save()
    print('Native creation and cleanup captured in ' + str(path))


if __name__ == '__main__':
    main()
