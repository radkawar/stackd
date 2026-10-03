#!/usr/bin/env python3
"""Capture IAM string comparison behavior using the shared owned-resource probe."""
import json
from pathlib import Path
import uuid

from iam_conditions_probe import capture_conditions, require


def string_pairs():
    for expected, actual in [
        ('prod', 'PrOd'), ('I', 'ı'), ('i', 'İ'), ('İ', 'i\u0307'),
        ('K', 'K'), ('s', 'ſ'), ('ß', 'ẞ'), ('ß', 'SS'),
        ('Σ', 'ς'), ('Σ', 'σ'), ('ΟΣ', 'ος'), ('ΟΣ', 'οσ'),
        ('ΟΣΑ', 'οσα'), ('É', 'é'), ('é', 'e\u0301'),
        ('𐐀', '𐐨'), ('𐐀', '𐐀'), ('AΣ𐐀', 'aς𐐀'),
        ('AΣ𐐀', 'aσ𐐀'), ('𐐀Σ', '𐐀σ'), ('𐐀Σ', '𐐀ς'),
    ]:
        yield ('StringEqualsIgnoreCase', 'StringNotEqualsIgnoreCase'), expected, actual
    for expected, actual in [
        ('?', '𐐀'), ('??', '𐐀'), ('?', 'é'), ('?', 'e\u0301'),
        ('a?b', 'a𐐀b'), ('a??b', 'a𐐀b'), ('a*?b', 'a𐐀b'),
        ('a?*b', 'a𐐀b'), ('a*b', 'a/b'), ('a?b', 'a:b'),
        ('𐐀?', '𐐀x'), ('𐐀?', '𐐀𐐨'), ('a*b', 'a\nb'),
        ('a?b', 'a\nb'), ('a[b]', 'ab'), ('a\\*b', 'a*b'),
    ]:
        yield ('StringLike', 'StringNotLike'), expected, actual
    for expected, actual in [('𐐀', '𐐀'), ('𐐀', '𐐨'), ('é', 'e\u0301')]:
        yield ('StringEquals', 'StringNotEquals'), expected, actual


def string_cases():
    for operators, expected, actual in string_pairs():
        for operator in operators:
            for deny in [False, True]:
                yield {'condition': {operator: {'aws:RequestTag/value': expected}},
                       'tags': [{'Key': 'value', 'Value': actual}], 'deny': deny}
    for operator, expected, actual in [
        ('StringEqualsIgnoreCase', 'S', 'ſ'),
        ('StringEqualsIgnoreCase', 'ΟΣ', 'ος'),
        ('StringLike', 'a?', 'a𐐀'),
        ('StringLike', 'a??', 'a𐐀'),
    ]:
        for quantifier in ['ForAnyValue:', 'ForAllValues:']:
            for deny in [False, True]:
                yield {'condition': {quantifier + operator: {'aws:TagKeys': expected}},
                       'tags': [{'Key': actual, 'Value': 'capture'}], 'deny': deny}
    for operator, pattern, actual in [
        ('StringEqualsIgnoreCase', 'S', 'ſ'),
        ('StringEqualsIgnoreCase', 'ΟΣ', 'ος'),
        ('StringEqualsIgnoreCase', '𐐀', '𐐨'),
        ('StringLike', '𐐀', '𐐀x'),
    ]:
        value = '${aws:RequestTag/pattern}' + ('?' if operator == 'StringLike' else '')
        for deny in [False, True]:
            yield {'condition': {operator: {'aws:RequestTag/value': value}},
                   'tags': [{'Key': 'pattern', 'Value': pattern}, {'Key': 'value', 'Value': actual}],
                   'deny': deny}


def string_simulations():
    for operators, expected, actual in string_pairs():
        actions = ['s3:GetObject', 's3:PutObject']
        statements = [{'Effect': 'Allow', 'Action': action, 'Resource': '*',
                       'Condition': {operator: {'aws:RequestTag/value': expected}}}
                      for action, operator in zip(actions, operators)]
        yield {'PolicyInputList': [json.dumps({'Version': '2012-10-17', 'Statement': statements})],
               'ActionNames': actions,
               'ContextEntries': [{'ContextKeyName': 'aws:RequestTag/value',
                                   'ContextKeyValues': [actual], 'ContextKeyType': 'string'}]}
    yield from resource_simulations()


def resource_simulations():
    prefix = 'arn:aws:s3:::stackd-string-hypothetical/'
    for pattern, value in [('?', '𐐀'), ('??', '𐐀'), ('𐐀', '𐐀'),
                           ('𐐀?', '𐐀x'), ('𐐀?', '𐐀𐐨'), ('*?', '𐐀')]:
        for resource_selector in [False, True]:
            statements = []
            for action, negated in [('s3:GetObject', False), ('s3:PutObject', True)]:
                statement = {'Effect': 'Allow', 'Action': action}
                if resource_selector:
                    statement['NotResource' if negated else 'Resource'] = prefix + pattern
                else:
                    statement['Resource'] = '*'
                    statement['Condition'] = {'ArnNotLike' if negated else 'ArnLike':
                                              {'aws:SourceArn': prefix + pattern}}
                statements.append(statement)
            yield {'PolicyInputList': [json.dumps({'Version': '2012-10-17', 'Statement': statements})],
                   'ActionNames': ['s3:GetObject', 's3:PutObject'], 'ResourceArns': [prefix + value],
                   'ContextEntries': [{'ContextKeyName': 'aws:SourceArn', 'ContextKeyType': 'string',
                                       'ContextKeyValues': [prefix + value]}]}


def capture_resource_reports(account):
    from aws_cli import require_account
    identity = require_account(account)
    name = 'stackd-string-report-' + uuid.uuid4().hex[:12]
    created = attached = False
    rows = []
    try:
        user = require('iam', 'create-user', {'UserName': name})['User']
        created = True
        for allowed, denied in [('𐐀', '?'), ('𐐀', '??'), ('𐐀x', '𐐀?'), ('𐐀𐐨', '𐐀?')]:
            document = {'Version': '2012-10-17', 'Statement': [
                {'Effect': effect, 'Action': 's3:GetObject', 'Resource': 'arn:aws:s3:::stackd-string-hypothetical/' + pattern}
                for effect, pattern in [('Allow', allowed), ('Deny', denied)]]}
            require('iam', 'put-user-policy', {'UserName': name, 'PolicyName': 'strings',
                                              'PolicyDocument': json.dumps(document)})
            attached = True
            result = require('iam', 'list-policies-granting-service-access',
                             {'Arn': user['Arn'], 'ServiceNamespaces': ['s3']})
            for service in result['PoliciesGrantingServiceAccess']:
                for policy in service['Policies']:
                    if policy.get('EntityName') == name:
                        policy['EntityName'] = 'condition-target'
            rows.append({'document': document, 'output': result})
            print(json.dumps(rows[-1]), flush=True)
    finally:
        if attached:
            require('iam', 'delete-user-policy', {'UserName': name, 'PolicyName': 'strings'})
        if created:
            require('iam', 'delete-user', {'UserName': name})
    print('Owned policy-discovery user and inline policy deleted')
    return rows


if __name__ == '__main__':
    import argparse
    from aws_cli import require_account
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--account", required=True)
    probe_args = parser.parse_args()
    require_account(probe_args.account)
    path = Path('.stackd/probes/iam/condition_strings.json')
    capture_conditions(string_cases(), path, string_simulations(), account=probe_args.account)
    capture = json.loads(path.read_text())
    capture['resource_reports'] = capture_resource_reports(probe_args.account)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(capture, indent=2) + '\n')
