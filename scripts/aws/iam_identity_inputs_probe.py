#!/usr/bin/env python3
"""Capture user/group name and path boundaries with owned, keyless identities."""
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
    suffix = uuid.uuid4().hex[:12]
    paths = ['/team/', '/team', 'team/', '/ space/', '/del\x7f/', '/é/', '//', '/a//b/', '/team/\n', '/line\n/']
    capture = {'source': 'AWS IAM CreateUser/CreateGroup and identity updates',
               'retrieved_at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
               'region': 'us-east-1', 'scope': 'Owned keyless users and empty groups; no attached policies or other resources.',
               'documentation': ['https://docs.aws.amazon.com/IAM/latest/APIReference/API_CreateUser.html',
                                 'https://docs.aws.amazon.com/IAM/latest/APIReference/API_UpdateUser.html',
                                 'https://docs.aws.amazon.com/IAM/latest/APIReference/API_CreateGroup.html'],
               'creates': [], 'updates': [], 'cleanup': False}
    owned = []
    try:
        for kind in ['User', 'Group']:
            name_field = kind + 'Name'
            for index, path in enumerate(paths):
                name = 'stackd-input-' + suffix + '-' + str(index)
                code, out = call('iam', 'create-' + kind.lower(), {name_field: name, 'Path': path})
                row = {'kind': kind, 'path': path, 'code': code}
                if code == 'Success':
                    owned.append((kind, name))
                    row['stored_path'] = out[kind]['Path']
                capture['creates'].append(row)
                print(json.dumps(row), flush=True)
            for name_suffix in ['\n', 'é']:
                name = 'stackd-name-' + suffix + name_suffix
                code, out = call('iam', 'create-' + kind.lower(), {name_field: name})
                row = {'kind': kind, 'name_suffix': name_suffix, 'code': code}
                if code == 'Success':
                    owned.append((kind, name))
                    row['stored_path'] = out[kind]['Path']
                row['lookup_code'], _ = call('iam', 'get-' + kind.lower(), {name_field: name})
                capture['creates'].append(row)
                print(json.dumps(row), flush=True)
            name = 'stackd-update-' + suffix
            require('iam', 'create-' + kind.lower(), {name_field: name, 'Path': '/initial/'})
            owned.append((kind, name))
            for path in paths:
                code, _ = call('iam', 'update-' + kind.lower(), {name_field: name, 'NewPath': path})
                stored = require('iam', 'get-' + kind.lower(), {name_field: name})[kind]['Path']
                row = {'kind': kind, 'path': path, 'code': code, 'stored_path': stored}
                capture['updates'].append(row)
                print(json.dumps(row), flush=True)
        for size in [64, 65, 128, 129]:
            prefix = 'stackd-name-' + suffix + '-'
            name = prefix + 'x' * (size - len(prefix))
            code, _ = call('iam', 'create-user', {'UserName': name})
            if code == 'Success':
                owned.append(('User', name))
            row = {'kind': 'User', 'name_length': size, 'code': code}
            capture['creates'].append(row)
            print(json.dumps(row), flush=True)
    finally:
        for kind, name in reversed(owned):
            require('iam', 'delete-' + kind.lower(), {kind + 'Name': name})
        capture['cleanup'] = True
        Path('.stackd/probes/iam/identity_inputs.json').parent.mkdir(parents=True, exist_ok=True)
        Path('.stackd/probes/iam/identity_inputs.json').write_text(json.dumps(capture, indent=2) + '\n')
    print('Owned users and groups deleted')


if __name__ == '__main__':
    main()
