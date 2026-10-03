#!/usr/bin/env python3
"""Capture Organizations delegation with a temporary policy scoped to owned resources.

Requires an ALL-features management account with no existing resource policy and
an existing member access role. Creates only owned IAM roles, an unattached SCP
and a temporary delegation policy; no accounts move and no SCPs are attached.
"""
import copy
import datetime
import json
import os
import time
import uuid

from iam_conditions_probe import call as iam_call
from organizations_inputs_probe import call, required, probe_parser, verified_account, capture_path
from signed_requests import signed_post


def org_call(action, parameters, credentials=None):
    if credentials is None:
        return call(action, parameters)
    environment = {k: v for k, v in os.environ.items() if not k.startswith('AWS_')}
    environment.update(AWS_ACCESS_KEY_ID=credentials['AccessKeyId'], AWS_SECRET_ACCESS_KEY=credentials['SecretAccessKey'],
                       AWS_SESSION_TOKEN=credentials['SessionToken'], AWS_EC2_METADATA_DISABLED='true')
    response = signed_post('organizations.us-east-1.amazonaws.com', 'organizations', json.dumps(parameters).encode(), {
        'content-type': 'application/x-amz-json-1.1', 'x-amz-target': 'AWSOrganizationsV20161128.' + action}, environment)
    result = json.loads(response.body or '{}')
    return {'code': result.get('__type', 'Success').split('#')[-1], 'status': response.status, 'output': result}


def cli(service, operation, parameters, credentials=None):
    code, output = iam_call(service, operation, parameters, credentials)
    if code != 'Success': raise RuntimeError(operation + ': ' + code)
    return output


def main():
    args = probe_parser('organizations_resource_policy.json').parse_args()
    management = verified_account(args.account)
    organization = required('DescribeOrganization', {})['Organization']
    if organization['MasterAccountId'] != management or organization['FeatureSet'] != 'ALL': raise RuntimeError('An ALL-features management account is required')
    before = call('DescribeResourcePolicy', {})
    if before['code'] != 'ResourcePolicyNotFoundException': raise RuntimeError('The organization already has a resource policy; refusing to replace it')
    accounts = required('ListAccounts', {})['Accounts']
    member = next(a['Id'] for a in accounts if a['Id'] != management and a['State'] == 'ACTIVE' and a['JoinedMethod'] == 'CREATED')
    member_admin = cli('sts', 'assume-role', {'RoleArn': 'arn:aws:iam::' + member + ':role/OrganizationAccountAccessRole', 'RoleSessionName': 'stackd-delegation-setup', 'DurationSeconds': 900})['Credentials']
    prefix = 'stackd-org-delegation-' + uuid.uuid4().hex[:10]
    role_arn = 'arn:aws:iam::' + member + ':role/' + prefix
    replacements = {management: '111111111111', member: '222222222222', organization['Id']: 'ORGANIZATION_ID', prefix: 'OWNED_NAME'}
    capture = {'retrieved_at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
               'source': 'Owned native AWS Organizations delegation policy and member IAM role',
               'scope': 'Temporary delegation is restricted to the owned actor ARN and owned policy; identity grants the owned policy read and organization listing; account-list contents are omitted. No account/OU/attachment changes.',
               'initial': before['code'], 'lifecycle': [], 'validation': [], 'enforcement': [], 'cleanup': False}
    cleanup = []
    resource_policy_created = False
    def normalized(value):
        text = json.dumps(value)
        for actual, expected in sorted(replacements.items(), key=lambda item: -len(item[0])): text = text.replace(actual, expected)
        return json.loads(text)
    def record(section, row):
        capture[section].append(normalized(row))
        print(f"{section} {len(capture[section])}: {row.get('case', row.get('action'))} {row['code']}", flush=True)
    def result_fields(result):
        output = result['output']
        if 'Accounts' in output: output = {'AccountCount': len(output['Accounts'])}
        return {'code': result['code'], 'status': result['status'], 'output': output}
    def observe_actor(case, action, parameters, actor, expected):
        deadline = time.monotonic() + 60
        polls = []
        while True:
            result = org_call(action, parameters, actor)
            polls.append(result['code'])
            if result['code'] == expected or time.monotonic() >= deadline: break
            time.sleep(1)
        record('enforcement', {'case': case, 'action': action, **result_fields(result), 'polls': polls})
        if result['code'] != expected: raise RuntimeError(case + ': ' + result['code'])
        return result
    try:
        record('lifecycle', {'action': 'DeleteResourcePolicy', **result_fields(call('DeleteResourcePolicy', {}))})
        trust = json.dumps({'Version': '2012-10-17', 'Statement': [{'Effect': 'Allow', 'Principal': {'AWS': 'arn:aws:iam::' + management + ':root'}, 'Action': 'sts:AssumeRole'}]})
        cli('iam', 'create-role', {'RoleName': prefix, 'AssumeRolePolicyDocument': trust}, member_admin)
        cleanup.append(('iam', 'delete-role', {'RoleName': prefix}, member_admin))
        content = '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}'
        target = required('CreatePolicy', {'Name': prefix, 'Description': 'Owned delegation probe', 'Type': 'SERVICE_CONTROL_POLICY', 'Content': content})['Policy']
        target_id, target_arn = target['PolicySummary']['Id'], target['PolicySummary']['Arn']
        replacements[target_id] = 'POLICY_ID'
        cleanup.append(('organizations', 'DeletePolicy', {'PolicyId': target_id}, None))
        statement = {'Effect': 'Allow', 'Principal': {'AWS': member}, 'Action': 'organizations:DescribePolicy', 'Resource': target_arn,
                     'Condition': {'ArnEquals': {'aws:PrincipalArn': role_arn}}}
        base = {'Version': '2012-10-17', 'Statement': [statement]}
        body = json.dumps(base)
        result = call('PutResourcePolicy', {'Content': body, 'Tags': [{'Key': 'stackd-probe', 'Value': prefix}]})
        if result['code'] != 'Success': raise RuntimeError('Initial PutResourcePolicy: ' + result['code'] + ': ' + result['output'].get('Message', ''))
        resource_policy_created = True
        rp = result['output']['ResourcePolicy']['ResourcePolicySummary']
        replacements[rp['Id']] = 'RESOURCE_POLICY_ID'
        record('lifecycle', {'action': 'PutResourcePolicy', 'input': {'Content': body, 'Tags': [{'Key': 'stackd-probe', 'Value': prefix}]}, **result_fields(result)})
        record('lifecycle', {'action': 'DescribeResourcePolicy', **result_fields(call('DescribeResourcePolicy', {}))})
        record('lifecycle', {'action': 'ListTagsForResource', **result_fields(call('ListTagsForResource', {'ResourceId': rp['Id']}))})
        for tags in [[], [{'Key': 'another', 'Value': 'rejected'}]]:
            record('lifecycle', {'action': 'PutResourcePolicy', 'input': {'Content': body, 'Tags': tags}, **result_fields(call('PutResourcePolicy', {'Content': body, 'Tags': tags}))})
        cases = [('base', {})]
        for field, values in [('Effect', ['Deny']), ('Principal', ['*', {'AWS': '*'}, {'AWS': role_arn}, {'AWS': management}, {'AWS': '123456789012'}, {'Service': 'kms.amazonaws.com'}]),
                              ('Action', ['organizations:ListAccounts', 'organizations:EnablePolicyType', 'organizations:CreateAccount', 'organizations:*', 'organizations:Describe*', 's3:GetObject']),
                              ('Resource', ['*']), ('Condition', [{'StringEquals': {'s3:prefix': 'irrelevant'}}, {'StringEquals': {'organizations:PolicyType': 'SERVICE_CONTROL_POLICY'}}])]:
            for value in values: cases.append((field + '-' + str(len(cases)), {field: value}))
        cases += [('NotAction', {'Action': None, 'NotAction': 'organizations:DescribePolicy'}), ('NotResource', {'Resource': None, 'NotResource': target_arn}),
                  ('NotPrincipal', {'Principal': None, 'NotPrincipal': {'AWS': member}})]
        for case, changes in cases:
            doc = copy.deepcopy(base)
            for key, value in changes.items():
                if value is None: doc['Statement'][0].pop(key, None)
                else: doc['Statement'][0][key] = value
            # Every policy retains an actor-ARN condition, including condition validation cases.
            doc['Statement'][0].setdefault('Condition', {})['ArnEquals'] = {'aws:PrincipalArn': role_arn}
            result = call('PutResourcePolicy', {'Content': json.dumps(doc)})
            record('validation', {'case': case, 'document': doc, **result_fields(result)})
        required('PutResourcePolicy', {'Content': body})
        deadline = time.monotonic() + 60
        while True:
            code, assumed = iam_call('sts', 'assume-role', {'RoleArn': role_arn, 'RoleSessionName': 'stackd-delegation-actor', 'DurationSeconds': 900})
            if code == 'Success': break
            if time.monotonic() > deadline: raise RuntimeError('Owned actor trust did not propagate')
            time.sleep(1)
        actor = assumed['Credentials']
        observe_actor('resource-grant-without-identity', 'DescribePolicy', {'PolicyId': target_id}, actor, 'AccessDeniedException')
        identity_policy = {'Version': '2012-10-17', 'Statement': [{'Effect': 'Allow', 'Action': 'organizations:DescribePolicy', 'Resource': target_arn}]}
        cli('iam', 'put-role-policy', {'RoleName': prefix, 'PolicyName': prefix, 'PolicyDocument': json.dumps(identity_policy)}, member_admin)
        cleanup.insert(0, ('iam', 'delete-role-policy', {'RoleName': prefix, 'PolicyName': prefix}, member_admin))
        observe_actor('resource-and-identity-grant', 'DescribePolicy', {'PolicyId': target_id}, actor, 'Success')
        denied = copy.deepcopy(base); denied['Statement'][0]['Condition']['ArnEquals']['aws:PrincipalArn'] = role_arn + '-unmatched'
        required('PutResourcePolicy', {'Content': json.dumps(denied)})
        observe_actor('resource-grant-revoked', 'DescribePolicy', {'PolicyId': target_id}, actor, 'AccessDeniedException')
        required('PutResourcePolicy', {'Content': body})
        observe_actor('resource-grant-restored', 'DescribePolicy', {'PolicyId': target_id}, actor, 'Success')
        # A wildcard principal must not bypass the member's own IAM/session restrictions.
        listing = copy.deepcopy(base)
        listing['Statement'][0].update(Principal='*', Action='organizations:ListAccounts', Resource='*')
        required('PutResourcePolicy', {'Content': json.dumps(listing)})
        observe_actor('wildcard-resource-without-identity', 'ListAccounts', {}, actor, 'AccessDeniedException')
        identity_policy['Statement'].append({'Effect': 'Allow', 'Action': 'organizations:ListAccounts', 'Resource': '*'})
        cli('iam', 'put-role-policy', {'RoleName': prefix, 'PolicyName': prefix, 'PolicyDocument': json.dumps(identity_policy)}, member_admin)
        observe_actor('wildcard-resource-with-identity', 'ListAccounts', {}, actor, 'Success')
        limited = cli('sts', 'assume-role', {'RoleArn': role_arn, 'RoleSessionName': 'stackd-delegation-limited', 'DurationSeconds': 900,
            'Policy': json.dumps({'Version': '2012-10-17', 'Statement': [{'Effect': 'Allow', 'Action': 'organizations:DescribePolicy', 'Resource': target_arn}]})})['Credentials']
        observe_actor('wildcard-resource-with-restrictive-session', 'ListAccounts', {}, limited, 'AccessDeniedException')
        for case, key, value in [('resource-account-condition', 'StringEquals', {'aws:ResourceAccount': management}),
                                 ('missing-resource-account-condition', 'Null', {'aws:ResourceAccount': 'true'})]:
            candidate = copy.deepcopy(listing)
            candidate['Statement'][0]['Condition'][key] = value
            required('PutResourcePolicy', {'Content': json.dumps(candidate)})
            results = []
            for attempt in range(3):
                if attempt: time.sleep(2)
                result = org_call('ListAccounts', {}, actor)
                results.append(result['code'])
            record('enforcement', {'case': case, 'action': 'ListAccounts', **result_fields(result), 'polls': results})
        management_deny = {'Version': '2012-10-17', 'Statement': [{'Effect': 'Deny', 'Principal': '*', 'Action': 'organizations:DescribePolicy',
            'Resource': target_arn, 'Condition': {'StringEquals': {'aws:PrincipalAccount': management}}}]}
        required('PutResourcePolicy', {'Content': json.dumps(management_deny)})
        results = []
        for attempt in range(3):
            if attempt: time.sleep(2)
            result = call('DescribePolicy', {'PolicyId': target_id})
            results.append(result['code'])
        record('enforcement', {'case': 'management-resource-policy-deny', 'action': 'DescribePolicy', **result_fields(result), 'polls': results})
        required('PutResourcePolicy', {'Content': body})
        observe_actor('restore-before-deletion', 'DescribePolicy', {'PolicyId': target_id}, actor, 'Success')
        result = call('DeleteResourcePolicy', {})
        record('lifecycle' , {'action': 'DeleteResourcePolicy', **result_fields(result)})
        if result['code'] != 'Success': raise RuntimeError('Delegation cleanup failed')
        resource_policy_created = False
        observe_actor('resource-policy-deleted', 'DescribePolicy', {'PolicyId': target_id}, actor, 'AccessDeniedException')
        record('lifecycle', {'action': 'DescribeResourcePolicy', **result_fields(call('DescribeResourcePolicy', {}))})
        record('lifecycle', {'action': 'ListTagsForResource', **result_fields(call('ListTagsForResource', {'ResourceId': rp['Id']}))})
    finally:
        if resource_policy_created:
            required('DeleteResourcePolicy', {})
        # Delete inline permissions before their role, then the unattached SCP.
        for service, action, parameters, credentials in cleanup:
            if service == 'organizations': required(action, parameters)
            else: cli(service, action, parameters, credentials)
        absent = call('DescribeResourcePolicy', {})['code'] == 'ResourcePolicyNotFoundException'
        capture['cleanup'] = absent
        capture_path(args.output).write_text(json.dumps(capture, indent=2) + '\n')
        print('Owned roles/policies deleted; delegation policy absent:', absent, flush=True)


if __name__ == '__main__':
    main()
