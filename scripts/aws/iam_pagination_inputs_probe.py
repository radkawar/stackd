#!/usr/bin/env python3
"""Capture Query pagination on owned IAM users, tags and service credentials."""
import datetime
import json
from pathlib import Path
import sys
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
    prefix = 'stackd-pages-' + uuid.uuid4().hex[:12]
    path = '/' + prefix + '/'
    users, credentials = [], []
    capture = {'source': 'Signed AWS IAM Query requests on owned users, tags and credentials',
               'retrieved_at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
               'observations': [], 'cleanup': False}

    def observe(case, action, parameters, collection, first=None):
        result = raw_query(action, parameters)
        row = {'case': case, 'operation': ''.join(word.title() for word in action.split('-')),
               'code': result['code'], 'http_status': result['http_status']}
        row['query'] = {key: ('<marker>' if key == 'Marker' else '<path>' if value == path else
                              '<user-' + value[-1] + '>' if value in users else value)
                        for key, value in parameters.items()}
        if 'Marker' in parameters:
            row['marker_source'] = {'list-users': 'users_first', 'list-user-tags': 'tags_first',
                                    'list-service-specific-credentials': 'credentials_first'}[action]
        output = result.get('output', {})
        items = output.get(collection) or []
        if result['code'] == 'Success':
            row['count'] = len(items)
            row['is_truncated'] = output.get('IsTruncated', False)
            if first is not None:
                row['overlap'] = any(item in first for item in items)
        capture['observations'].append(row)
        print(json.dumps(row), flush=True)
        return output.get('Marker'), items

    try:
        for suffix in ['a', 'b', 'c']:
            name = prefix + '-' + suffix
            require('iam', 'create-user', {'UserName': name, 'Path': path,
                                          'Tags': [{'Key': k, 'Value': k} for k in ['a', 'b', 'c']]})
            users.append(name)
        for value in ['1', '01', '+1', ' 1 ', '1.0', '1e0', '0', '1001', '2147483648']:
            observe('users_size_' + value, 'list-users', {'PathPrefix': path, 'MaxItems': value}, 'Users')
        token, first = observe('users_first', 'list-users', {'PathPrefix': path, 'MaxItems': '1'}, 'Users')
        for value in ['01', '+1', '2']:
            observe('users_next_' + value, 'list-users', {'PathPrefix': path, 'MaxItems': value, 'Marker': token}, 'Users', first)
        observe('users_unknown_filter', 'list-users', {'PathPrefix': path, 'MaxItems': '1', 'Marker': token,
                                                       'Tags.member.1.Key': 'ignored', 'Tags.member.1.Value': 'ignored'}, 'Users', first)
        token, first = observe('tags_first', 'list-user-tags', {'UserName': users[0], 'MaxItems': '1'}, 'Tags')
        observe('tags_next', 'list-user-tags', {'UserName': users[0], 'MaxItems': '+1', 'Marker': token}, 'Tags', first)
        for _ in range(2):
            credential = require('iam', 'create-service-specific-credential', {
                'UserName': users[0], 'ServiceName': 'bedrock.amazonaws.com', 'CredentialAgeDays': 1})['ServiceSpecificCredential']
            credentials.append(credential['ServiceSpecificCredentialId'])
        token, first = observe('credentials_first', 'list-service-specific-credentials',
                               {'UserName': users[0], 'AllUsers': 'false', 'MaxItems': '1'}, 'ServiceSpecificCredentials')
        if not token:
            raise RuntimeError('Owned credential listing did not provide a continuation marker')
        for value in ['false', '0']:
            observe('credentials_next_' + value, 'list-service-specific-credentials',
                    {'UserName': users[0], 'AllUsers': value, 'MaxItems': '1', 'Marker': token}, 'ServiceSpecificCredentials', first)
    finally:
        for identifier in credentials:
            require('iam', 'delete-service-specific-credential', {'UserName': users[0], 'ServiceSpecificCredentialId': identifier})
        for name in reversed(users):
            require('iam', 'delete-user', {'UserName': name})
        capture['cleanup'] = True
        Path('.stackd/probes/iam/pagination_inputs.json').parent.mkdir(parents=True, exist_ok=True)
        Path('.stackd/probes/iam/pagination_inputs.json').write_text(json.dumps(capture, indent=2) + '\n')
    print('Owned users and credentials deleted')


if __name__ == '__main__':
    main()
