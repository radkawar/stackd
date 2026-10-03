#!/usr/bin/env python3
"""Capture delegation writes against owned roles, policies and an empty OU.

Uses the designated management account and an existing member access role. No
accounts move; the only SCP attachment is to the empty OU created by this probe.
The temporary organization delegation policy requires the owned actor role ARN.
"""
import copy
import datetime
import json
import time
import uuid

from iam_conditions_probe import call as iam_call
from organizations_inputs_probe import call, required, probe_parser, verified_account, capture_path
from organizations_resource_policy_probe import cli, org_call


def main():
    args = probe_parser('organizations_delegation_writes.json').parse_args()
    management = verified_account(args.account)
    organization = required('DescribeOrganization', {})['Organization']
    if organization['MasterAccountId'] != management or organization['FeatureSet'] != 'ALL': raise RuntimeError('An ALL-features management account is required')
    if call('DescribeResourcePolicy', {})['code'] != 'ResourcePolicyNotFoundException': raise RuntimeError('Existing delegation policy must not be replaced')
    member = next(a['Id'] for a in required('ListAccounts', {})['Accounts'] if a['Id'] != management and a['State'] == 'ACTIVE' and a['JoinedMethod'] == 'CREATED')
    member_admin = cli('sts', 'assume-role', {'RoleArn': 'arn:aws:iam::' + member + ':role/OrganizationAccountAccessRole', 'RoleSessionName': 'stackd-write-setup', 'DurationSeconds': 900})['Credentials']
    prefix = 'stackd-org-writes-' + uuid.uuid4().hex[:10]
    role_arn = 'arn:aws:iam::' + member + ':role/' + prefix
    policy_arn = 'arn:aws:organizations::' + management + ':policy/' + organization['Id'] + '/service_control_policy/*'
    rp_arn = 'arn:aws:organizations::' + management + ':resourcepolicy/' + organization['Id'] + '/*'
    replacements = {management: '111111111111', member: '222222222222', organization['Id']: 'ORGANIZATION_ID', prefix: 'OWNED_NAME'}
    capture = {'retrieved_at': datetime.datetime.now(datetime.timezone.utc).isoformat(), 'source': 'Owned native Organizations delegation writes',
               'scope': 'Owned member/management roles, policies and empty OU; only the owned empty OU receives an SCP attachment. No account moves or existing policy changes.', 'observations': [], 'cleanup': False}
    roles, policies, unit_id, attached, rp_created = [], [], None, None, False
    def observe(case, action, parameters, actor=None, expected=None):
        polls, deadline = [], time.monotonic() + 60
        while True:
            result = org_call(action, parameters, actor)
            polls.append(result['code'])
            if expected is None or result['code'] == expected or time.monotonic() >= deadline: break
            time.sleep(1)
        output = result['output']
        if 'ResourcePolicy' in output:
            replacements[output['ResourcePolicy']['ResourcePolicySummary']['Id']] = 'RESOURCE_POLICY_ID'
        if action == 'CreatePolicy' and 'Policy' in output:
            replacements[output['Policy']['PolicySummary']['Id']] = 'POLICY_ID'
        row = {'case': case, 'action': action, 'input': parameters, **result, 'polls': polls}
        text = json.dumps(row)
        for actual, normalized in sorted(replacements.items(), key=lambda item: -len(item[0])): text = text.replace(actual, normalized)
        capture['observations'].append(json.loads(text))
        print(case + ': ' + result['code'], flush=True)
        if expected is not None and result['code'] != expected: raise RuntimeError(case + ': ' + result['code'])
        return result
    def assume(arn):
        deadline = time.monotonic() + 60
        while True:
            code, out = iam_call('sts', 'assume-role', {'RoleArn': arn, 'RoleSessionName': 'stackd-write-actor', 'DurationSeconds': 900})
            if code == 'Success': return out['Credentials']
            if time.monotonic() >= deadline: raise RuntimeError('Owned role trust did not propagate: ' + code)
            time.sleep(1)
    def delegate(statements):
        nonlocal rp_created
        statements = copy.deepcopy(statements)
        for st in statements:
            st['Principal'] = {'AWS': member}
            st.setdefault('Condition', {})['ArnEquals'] = {'aws:PrincipalArn': role_arn}
        required('PutResourcePolicy', {'Content': json.dumps({'Version': '2012-10-17', 'Statement': statements})})
        rp_created = True
    try:
        trust = json.dumps({'Statement': [{'Effect': 'Allow', 'Principal': {'AWS': 'arn:aws:iam::' + management + ':root'}, 'Action': 'sts:AssumeRole'}]})
        for account, credentials in [(management, None), (member, member_admin)]:
            cli('iam', 'create-role', {'RoleName': prefix, 'AssumeRolePolicyDocument': trust}, credentials)
            roles.append((credentials, False))
            grant = {'Statement': [{'Effect': 'Allow', 'Action': 'organizations:PutResourcePolicy', 'Resource': rp_arn}]} if account == management else {'Statement': [{'Effect': 'Allow', 'Action': ['organizations:CreatePolicy', 'organizations:DescribePolicy', 'organizations:UpdatePolicy', 'organizations:DeletePolicy', 'organizations:TagResource', 'organizations:UntagResource', 'organizations:ListTagsForResource', 'organizations:AttachPolicy', 'organizations:DetachPolicy'], 'Resource': '*'}]}
            cli('iam', 'put-role-policy', {'RoleName': prefix, 'PolicyName': prefix, 'PolicyDocument': json.dumps(grant)}, credentials)
            roles[-1] = (credentials, True)
        manager, actor = assume('arn:aws:iam::' + management + ':role/' + prefix), assume(role_arn)
        inert = json.dumps({'Statement': [{'Effect': 'Allow', 'Principal': {'AWS': member}, 'Action': 'organizations:DescribePolicy', 'Resource': policy_arn,
            'Condition': {'ArnEquals': {'aws:PrincipalArn': 'arn:aws:iam::' + management + ':role/' + prefix}}}]})
        observe('put-only-without-tags', 'PutResourcePolicy', {'Content': inert}, manager, 'Success')
        rp_created = True
        required('DeleteResourcePolicy', {}); rp_created = False
        result = observe('put-only-with-initial-tags', 'PutResourcePolicy', {'Content': inert, 'Tags': [{'Key': 'stackd-probe', 'Value': prefix}]}, manager)
        if result['code'] == 'Success':
            rp_created = True
            required('DeleteResourcePolicy', {}); rp_created = False
        cli('iam', 'put-role-policy', {'RoleName': prefix, 'PolicyName': prefix, 'PolicyDocument': json.dumps({'Statement': [{'Effect': 'Allow', 'Action': ['organizations:PutResourcePolicy', 'organizations:TagResource'], 'Resource': rp_arn}]})})
        result = observe('put-and-tag-with-initial-tags', 'PutResourcePolicy', {'Content': inert, 'Tags': [{'Key': 'stackd-probe', 'Value': prefix}]}, manager, 'Success')
        if result['code'] == 'Success':
            rp_created = True
            rp = result['output']['ResourcePolicy']['ResourcePolicySummary']['Id']
            replacements[rp] = 'RESOURCE_POLICY_ID'
            observe('tag-resource-policy', 'TagResource', {'ResourceId': rp, 'Tags': [{'Key': 'team', 'Value': 'probe'}]}, expected='Success')
            observe('untag-resource-policy', 'UntagResource', {'ResourceId': rp, 'TagKeys': ['stackd-probe']}, expected='Success')
            observe('remaining-resource-policy-tags', 'ListTagsForResource', {'ResourceId': rp}, expected='Success')
            required('DeleteResourcePolicy', {}); rp_created = False
        for action in ['DescribeResponsibilityTransfer', 'ListAccountsWithInvalidEffectivePolicy', 'ListEffectivePolicyValidationErrors', 'ListInboundResponsibilityTransfers', 'ListOutboundResponsibilityTransfers']:
            candidate = json.loads(inert)
            candidate['Statement'][0]['Action'] = 'organizations:' + action
            result = observe('validate-' + action, 'PutResourcePolicy', {'Content': json.dumps(candidate)})
            if result['code'] == 'Success': rp_created = True
        if rp_created: required('DeleteResourcePolicy', {}); rp_created = False
        root = required('ListRoots', {})['Roots'][0]['Id']
        unit = required('CreateOrganizationalUnit', {'ParentId': root, 'Name': prefix})['OrganizationalUnit']
        unit_id = unit['Id']; replacements[unit_id] = 'UNIT_ID'
        create = {'Effect': 'Allow', 'Action': 'organizations:CreatePolicy', 'Resource': policy_arn, 'Condition': {'StringEquals': {'aws:RequestTag/stackd-probe': prefix}}}
        delegate([create])
        request = {'Name': prefix, 'Description': 'Owned delegation writes', 'Type': 'SERVICE_CONTROL_POLICY', 'Content': '{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}', 'Tags': [{'Key': 'stackd-probe', 'Value': prefix}]}
        result = observe('create-without-delegated-tag', 'CreatePolicy', request, actor)
        if result['code'] == 'Success': policies.append(result['output']['Policy']['PolicySummary']['Id'])
        tag = copy.deepcopy(create); tag['Action'] = 'organizations:TagResource'
        delegate([create, tag])
        request['Name'] += '-tagged'
        result = observe('create-with-delegated-tag', 'CreatePolicy', request, actor, 'Success')
        target = result['output']['Policy']['PolicySummary']; target_id = target['Id']; policies.append(target_id); replacements[target_id] = 'POLICY_ID'
        writes = {'Effect': 'Allow', 'Action': ['organizations:DescribePolicy', 'organizations:UpdatePolicy', 'organizations:DeletePolicy', 'organizations:TagResource', 'organizations:UntagResource', 'organizations:ListTagsForResource', 'organizations:AttachPolicy', 'organizations:DetachPolicy'], 'Resource': target['Arn']}
        delegate([writes])
        observe('update-policy', 'UpdatePolicy', {'PolicyId': target_id, 'Name': prefix + '-updated'}, actor, 'Success')
        observe('tag-policy', 'TagResource', {'ResourceId': target_id, 'Tags': [{'Key': 'team', 'Value': 'probe'}]}, actor, 'Success')
        observe('untag-policy', 'UntagResource', {'ResourceId': target_id, 'TagKeys': ['team']}, actor, 'Success')
        observe('attach-without-target-grant', 'AttachPolicy', {'PolicyId': target_id, 'TargetId': unit_id}, actor, 'AccessDeniedException')
        writes['Resource'] = [target['Arn'], unit['Arn']]
        delegate([writes])
        result = observe('attach-with-target-grant', 'AttachPolicy', {'PolicyId': target_id, 'TargetId': unit_id}, actor, 'Success'); attached = target_id
        observe('delete-attached-policy', 'DeletePolicy', {'PolicyId': target_id}, actor, 'PolicyInUseException')
        observe('detach-policy', 'DetachPolicy', {'PolicyId': target_id, 'TargetId': unit_id}, actor, 'Success'); attached = None
        observe('delete-policy', 'DeletePolicy', {'PolicyId': target_id}, actor, 'Success'); policies.remove(target_id)
        observe('describe-deleted-policy', 'DescribePolicy', {'PolicyId': target_id}, actor, 'AccessDeniedException')
    finally:
        if rp_created: required('DeleteResourcePolicy', {})
        if attached: required('DetachPolicy', {'PolicyId': attached, 'TargetId': unit_id})
        for policy in policies: required('DeletePolicy', {'PolicyId': policy})
        if unit_id: required('DeleteOrganizationalUnit', {'OrganizationalUnitId': unit_id})
        for credentials, inline in reversed(roles):
            if inline: cli('iam', 'delete-role-policy', {'RoleName': prefix, 'PolicyName': prefix}, credentials)
            cli('iam', 'delete-role', {'RoleName': prefix}, credentials)
        capture['cleanup'] = call('DescribeResourcePolicy', {})['code'] == 'ResourcePolicyNotFoundException'
        capture_path(args.output).write_text(json.dumps(capture, indent=2) + '\n')
        print('Owned roles, policies and empty OU deleted; delegation absent:', capture['cleanup'], flush=True)


if __name__ == '__main__':
    main()
