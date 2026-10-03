#!/usr/bin/env python3
"""Capture policy filters, inline-name matching and repeated identity mutations."""
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
    name = 'stackd-policy-' + suffix
    path = '/' + name + '/'
    allow = {'Version': '2012-10-17', 'Statement': [{'Effect': 'Allow', 'Action': 's3:GetObject',
             'Resource': 'arn:aws:s3:::' + name + '/*'}]}
    deny = dict(allow, Statement=[dict(allow['Statement'][0], Effect='Deny')])
    trust = {'Version': '2012-10-17', 'Statement': [{'Effect': 'Allow', 'Action': 'sts:AssumeRole',
             'Principal': {'Service': 'ec2.amazonaws.com'}}]}
    capture = {'source': 'AWS IAM policy management',
               'retrieved_at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
               'region': 'us-east-1',
               'scope': 'Owned keyless user, empty group, role and four managed policies; no data-plane resources.',
               'documentation': ['https://docs.aws.amazon.com/IAM/latest/APIReference/API_ListPolicies.html',
                                 'https://docs.aws.amazon.com/IAM/latest/APIReference/API_ListEntitiesForPolicy.html',
                                 'https://docs.aws.amazon.com/IAM/latest/APIReference/API_PutUserPolicy.html',
                                 'https://docs.aws.amazon.com/IAM/latest/APIReference/API_DetachUserPolicy.html'],
               'list_policies': [], 'entities': [], 'inline': [],
               'detach_missing': [], 'delete_boundary_missing': [], 'cleanup': False}
    identities, policies, attached, boundaries = [], {}, [], []

    def record(section, row):
        capture[section].append(row)
        print(section + ': ' + json.dumps(row), flush=True)

    try:
        for kind in ['User', 'Group', 'Role']:
            parameters = {kind + 'Name': name, 'Path': path}
            if kind == 'Role':
                parameters['AssumeRolePolicyDocument'] = json.dumps(trust)
            require('iam', 'create-' + kind.lower(), parameters)
            identities.append(kind)
        for label in ['unused', 'attached', 'boundary', 'both']:
            policy = require('iam', 'create-policy', {'PolicyName': name + '-' + label,
                             'Path': path, 'PolicyDocument': json.dumps(allow)})['Policy']
            policies[label] = policy['Arn']
        for kind in identities:
            code, _ = call('iam', 'detach-' + kind.lower() + '-policy',
                           {kind + 'Name': name, 'PolicyArn': policies['unused']})
            record('detach_missing', {'kind': kind, 'code': code})
            if kind != 'Group':
                code, _ = call('iam', 'delete-' + kind.lower() + '-permissions-boundary', {kind + 'Name': name})
                record('delete_boundary_missing', {'kind': kind, 'code': code})
            for policy_name, document in [('MixedName', allow), ('mixedname', deny)]:
                require('iam', 'put-' + kind.lower() + '-policy',
                        {kind + 'Name': name, 'PolicyName': policy_name, 'PolicyDocument': json.dumps(document)})
            names = require('iam', 'list-' + kind.lower() + '-policies', {kind + 'Name': name})['PolicyNames']
            get_code, output = call('iam', 'get-' + kind.lower() + '-policy',
                                    {kind + 'Name': name, 'PolicyName': 'MIXEDNAME'})
            delete_code, _ = call('iam', 'delete-' + kind.lower() + '-policy',
                                  {kind + 'Name': name, 'PolicyName': 'mIxEdNaMe'})
            remaining = require('iam', 'list-' + kind.lower() + '-policies', {kind + 'Name': name})['PolicyNames']
            row = {'kind': kind, 'names': names, 'get_mixed_code': get_code,
                   'delete_mixed_code': delete_code, 'remaining_names': remaining}
            if get_code == 'Success':
                row['returned_name'] = output['PolicyName']
                row['effect'] = output['PolicyDocument']['Statement'][0]['Effect']
            record('inline', row)
        for kind, label in [('User', 'attached'), ('Group', 'attached'), ('Role', 'attached'), ('Group', 'both')]:
            require('iam', 'attach-' + kind.lower() + '-policy', {kind + 'Name': name, 'PolicyArn': policies[label]})
            attached.append((kind, label))
        for kind, label in [('User', 'boundary'), ('Role', 'both')]:
            for _ in range(2):
                require('iam', 'put-' + kind.lower() + '-permissions-boundary',
                        {kind + 'Name': name, 'PermissionsBoundary': policies[label]})
            boundaries.append(kind)
        for only_attached in [None, False, True]:
            for usage in [None, 'PermissionsPolicy', 'PermissionsBoundary']:
                parameters = {'Scope': 'Local', 'PathPrefix': path}
                if only_attached is not None:
                    parameters['OnlyAttached'] = only_attached
                if usage is not None:
                    parameters['PolicyUsageFilter'] = usage
                code, output = call('iam', 'list-policies', parameters)
                labels = sorted(label for label, arn in policies.items()
                                if any(row['Arn'] == arn for row in output.get('Policies', [])))
                record('list_policies', {'only_attached': only_attached, 'usage': usage,
                                        'code': code, 'policies': labels})
        for label in policies:
            filters = [None, 'User', 'Group', 'Role', 'LocalManagedPolicy', 'AWSManagedPolicy'] if label == 'both' else [None]
            for entity_filter in filters:
                for usage in [None, 'PermissionsPolicy', 'PermissionsBoundary']:
                    parameters = {'PolicyArn': policies[label]}
                    if entity_filter is not None:
                        parameters['EntityFilter'] = entity_filter
                    if usage is not None:
                        parameters['PolicyUsageFilter'] = usage
                    code, output = call('iam', 'list-entities-for-policy', parameters)
                    record('entities', {'policy': label, 'filter': entity_filter, 'usage': usage, 'code': code,
                                        'users': len(output.get('PolicyUsers', [])),
                                        'groups': len(output.get('PolicyGroups', [])),
                                        'roles': len(output.get('PolicyRoles', []))})
        capture['counts'] = {}
        for label, arn in policies.items():
            policy = require('iam', 'get-policy', {'PolicyArn': arn})['Policy']
            capture['counts'][label] = {key: policy[key] for key in ['AttachmentCount', 'PermissionsBoundaryUsageCount']}
    finally:
        for kind in boundaries:
            require('iam', 'delete-' + kind.lower() + '-permissions-boundary', {kind + 'Name': name})
        for kind, label in attached:
            require('iam', 'detach-' + kind.lower() + '-policy', {kind + 'Name': name, 'PolicyArn': policies[label]})
        for kind in identities:
            for policy_name in require('iam', 'list-' + kind.lower() + '-policies', {kind + 'Name': name})['PolicyNames']:
                require('iam', 'delete-' + kind.lower() + '-policy', {kind + 'Name': name, 'PolicyName': policy_name})
            require('iam', 'delete-' + kind.lower(), {kind + 'Name': name})
        for arn in policies.values():
            require('iam', 'delete-policy', {'PolicyArn': arn})
        capture['cleanup'] = True
        Path('.stackd/probes/iam/policy_management.json').parent.mkdir(parents=True, exist_ok=True)
        Path('.stackd/probes/iam/policy_management.json').write_text(json.dumps(capture, indent=2) + '\n')
    print('Owned identities and policies deleted')


if __name__ == '__main__':
    main()
