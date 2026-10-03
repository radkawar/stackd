#!/usr/bin/env python3
"""Capture STS Query integer forms using an owned user with no permission policies."""
import argparse
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
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--account', required=True, help='AWS account ID authorized for this probe')
    args = parser.parse_args()
    account = require('sts', 'get-caller-identity', {})['Account']
    if account != args.account:
        raise RuntimeError('Unexpected native AWS account')
    destination = Path(__file__).resolve().parents[2] / '.stackd/probes/sts/query_inputs.json'
    destination.parent.mkdir(parents=True, exist_ok=True)
    name = 'stackd-sts-inputs-' + uuid.uuid4().hex[:12]
    capture = {'source': 'Signed AWS STS GetSessionToken Query requests',
               'retrieved_at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
               'region': 'us-east-1', 'scope': 'Owned user/key without permission policies; temporary credentials discarded.',
               'observations': [], 'cleanup': False}
    created = False
    key = None
    try:
        require('iam', 'create-user', {'UserName': name})
        created = True
        key = require('iam', 'create-access-key', {'UserName': name})['AccessKey']
        environment = dict(os.environ, AWS_ACCESS_KEY_ID=key['AccessKeyId'], AWS_SECRET_ACCESS_KEY=key['SecretAccessKey'])
        environment.pop('AWS_SESSION_TOKEN', None)
        environment.pop('AWS_PROFILE', None)
        deadline = time.monotonic() + 60
        while True:
            control = raw_query('get-session-token', {'DurationSeconds': '900'}, environment, service='sts')
            if control['code'] == 'Success':
                break
            if control['code'] != 'InvalidClientTokenId' or time.monotonic() >= deadline:
                raise RuntimeError('STS credential propagation control failed: ' + control['code'])
            time.sleep(1)
        for value in ['900', '0900', '+900', ' 900 ', '\t900\n', '900.0', '9e2', '2147483648', '0']:
            result = raw_query('get-session-token', {'DurationSeconds': value}, environment, service='sts')
            row = {'value': value, 'code': result['code'], 'http_status': result['http_status']}
            capture['observations'].append(row)
            print(json.dumps(row), flush=True)
    finally:
        if key:
            require('iam', 'delete-access-key', {'UserName': name, 'AccessKeyId': key['AccessKeyId']})
        if created:
            require('iam', 'delete-user', {'UserName': name})
        capture['cleanup'] = True
        destination.write_text(json.dumps(capture, indent=2) + '\n')
    print('Owned user/key deleted; temporary credentials discarded')


if __name__ == '__main__':
    main()
