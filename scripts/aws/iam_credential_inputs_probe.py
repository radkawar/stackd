#!/usr/bin/env python3
"""Capture IAM Query scalar parsing and credential conditions on an owned user."""
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
    name = 'stackd-credential-inputs-' + uuid.uuid4().hex[:12]
    capture = {'source': 'Signed AWS IAM Query requests; owned user, permission policy and credentials',
               'retrieved_at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
               'region': 'us-east-1', 'numeric_inputs': [], 'condition_inputs': [], 'boolean_inputs': [],
               'documentation': [
                   'https://docs.aws.amazon.com/IAM/latest/APIReference/API_CreateServiceSpecificCredential.html',
                   'https://docs.aws.amazon.com/IAM/latest/APIReference/API_ListServiceSpecificCredentials.html'],
               'cleanup': False}
    created = policy_created = False
    key = None
    credentials = set()

    def create(age, environment=None):
        parameters = {'UserName': name, 'ServiceName': 'bedrock.amazonaws.com', 'CredentialAgeDays': age}
        result = raw_query('create-service-specific-credential', parameters, environment)
        row = {'value': age, 'code': result['code'], 'http_status': result['http_status']}
        if result['code'] == 'Success':
            record = result['output']['ServiceSpecificCredential']
            identifier = record['ServiceSpecificCredentialId']
            credentials.add(identifier)
            start = datetime.datetime.fromisoformat(record['CreateDate'].replace('Z', '+00:00'))
            end = datetime.datetime.fromisoformat(record['ExpirationDate'].replace('Z', '+00:00'))
            row['expiration_seconds'] = int((end - start).total_seconds())
            require('iam', 'delete-service-specific-credential', {'UserName': name, 'ServiceSpecificCredentialId': identifier})
            credentials.remove(identifier)
        return row

    try:
        user = require('iam', 'create-user', {'UserName': name, 'Path': '/stackd-probes/'})['User']
        created = True
        values = ['1', ' 1 ', '\t1\n', '01', '+1', '1.0', '1e0', '0', '-1', '36601']
        for value in values:
            row = create(value)
            capture['numeric_inputs'].append(row)
            print('number: ' + json.dumps(row), flush=True)
        policy = {'Version': '2012-10-17', 'Statement': [
            {'Effect': 'Allow', 'Action': 'iam:ListServiceSpecificCredentials', 'Resource': user['Arn']},
            {'Effect': 'Allow', 'Action': 'iam:CreateServiceSpecificCredential', 'Resource': user['Arn'],
             'Condition': {'StringEquals': {'iam:ServiceSpecificCredentialAgeDays': '1',
                                          'iam:ServiceSpecificCredentialServiceName': 'bedrock.amazonaws.com'}}}]}
        require('iam', 'put-user-policy', {'UserName': name, 'PolicyName': 'CredentialInputs', 'PolicyDocument': json.dumps(policy)})
        policy_created = True
        key = require('iam', 'create-access-key', {'UserName': name})['AccessKey']
        environment = dict(os.environ, AWS_ACCESS_KEY_ID=key['AccessKeyId'], AWS_SECRET_ACCESS_KEY=key['SecretAccessKey'])
        environment.pop('AWS_SESSION_TOKEN', None)
        environment.pop('AWS_PROFILE', None)
        deadline = time.monotonic() + 60
        while raw_query('list-service-specific-credentials', {}, environment)['code'] != 'Success':
            if time.monotonic() >= deadline:
                raise RuntimeError('Owned user permissions did not propagate within the probe window')
            time.sleep(1)
        for value in values[:7]:
            row = create(value, environment)
            capture['condition_inputs'].append(row)
            print('condition: ' + json.dumps(row), flush=True)
        for value in ['true', 'false', ' true', 'true ', '\ttrue\n', 'True', 'TRUE', 'False', 'FALSE', '1', '0', '', 'null', 'anything']:
            result = raw_query('list-service-specific-credentials', {'AllUsers': value}, environment)
            row = {'value': value, 'code': result['code'], 'http_status': result['http_status']}
            capture['boolean_inputs'].append(row)
            print('boolean: ' + json.dumps(row), flush=True)
    finally:
        for identifier in credentials:
            require('iam', 'delete-service-specific-credential', {'UserName': name, 'ServiceSpecificCredentialId': identifier})
        if key:
            require('iam', 'delete-access-key', {'UserName': name, 'AccessKeyId': key['AccessKeyId']})
        if policy_created:
            require('iam', 'delete-user-policy', {'UserName': name, 'PolicyName': 'CredentialInputs'})
        if created:
            require('iam', 'delete-user', {'UserName': name})
        capture['cleanup'] = True
        Path('.stackd/probes/iam/credential_inputs.json').parent.mkdir(parents=True, exist_ok=True)
        Path('.stackd/probes/iam/credential_inputs.json').write_text(json.dumps(capture, indent=2) + '\n')
    print('Owned user, permission policy and credentials deleted')


if __name__ == '__main__':
    main()
