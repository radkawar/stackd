#!/usr/bin/env python3
"""Capture chat-policy publication for an unused Slack workspace on one member."""
import datetime
import json
import time
import uuid

from organizations_inputs_probe import call, required, probe_parser, verified_account, capture_path


def main():
    args = probe_parser('organizations_chat_effective.json').parse_args()
    owner = verified_account(args.account)
    root = required('ListRoots', {})['Roots'][0]
    organization = required('DescribeOrganization', {})['Organization']
    if organization['FeatureSet'] != 'ALL' or any(p['Type'] == 'CHATBOT_POLICY' for p in root['PolicyTypes']):
        raise RuntimeError('Requires ALL and disabled chat policies')
    accounts = required('ListAccounts', {})['Accounts']
    member = next(a['Id'] for a in accounts if a['Id'] != owner and a['State'] == 'ACTIVE' and a['JoinedMethod'] == 'CREATED')
    trusted = required('ListAWSServiceAccessForOrganization', {})['EnabledServicePrincipals']
    prefix = 'stackd-chat-policy-' + uuid.uuid4().hex[:10]
    workspace = 'T' + uuid.uuid4().hex.upper() + uuid.uuid4().hex.upper()
    replacements = {owner: '111111111111', member: '222222222222', root['Id']: 'r-example', prefix: 'stackd-chat-policy-owned'}
    capture = {'retrieved_at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
               'scope': 'Overrides only for a uniquely named unused Slack workspace; no client toggles, workspace allowlists, account moves or chat messages',
               'observations': [], 'cleanup': False}
    path = capture_path(args.output)
    owned, attached = [], []
    enabled = False
    def save():
        text = json.dumps(capture, indent=2)
        for actual, replacement in replacements.items(): text = text.replace(actual, replacement)
        path.write_text(text + '\n')
    def observe(label, action, parameters):
        result = call(action, parameters)
        capture['observations'].append(dict(case=label, action=action, input=parameters, **result))
        save()
        print(label + ': ' + result['code'], flush=True)
        return result
    def effective(label):
        time.sleep(20)
        observe(label, 'DescribeEffectivePolicy', {'TargetId': member, 'PolicyType': 'CHATBOT_POLICY'})
    def create(label, content):
        result = required('CreatePolicy', {'Name': prefix + '-' + label, 'Description': 'Unused workspace policy capture', 'Type': 'CHATBOT_POLICY', 'Content': json.dumps(content)})
        policy = result['Policy']['PolicySummary']['Id']
        owned.append(policy)
        replacements[policy] = 'POLICY_' + str(len(owned))
        capture['observations'].append(dict(case='create-' + label, action='CreatePolicy', input={'Name': prefix + '-' + label, 'Description': 'Unused workspace policy capture', 'Type': 'CHATBOT_POLICY', 'Content': json.dumps(content)}, code='Success', output=result))
        save()
        required('AttachPolicy', {'PolicyId': policy, 'TargetId': member})
        attached.append(policy)
        capture['observations'].append(dict(case='attach-' + label, action='AttachPolicy', input={'PolicyId': policy, 'TargetId': member}, code='Success', output={}))
        save()
        return policy
    try:
        observe('disabled', 'DescribeEffectivePolicy', {'TargetId': member, 'PolicyType': 'CHATBOT_POLICY'})
        required('EnablePolicyType', {'RootId': root['Id'], 'PolicyType': 'CHATBOT_POLICY'})
        enabled = True
        capture['observations'].append(dict(case='enable', action='EnablePolicyType', input={'RootId': root['Id'], 'PolicyType': 'CHATBOT_POLICY'}, code='Success', output={}))
        effective('empty')
        first = {'ChatBot': {'Platforms': {'Slack': {'Overrides': {workspace: {'Supported_Channel_Types': {'@@Assign': ['private']}, 'Supported_Role_Settings': {'@@Assign': ['user_role']}}}}}}}
        first_id = create('first', first)
        effective('first-published')
        second = {'chatbot': {'platforms': {'slack': {'overrides': {workspace: {'supported_role_settings': {'@@append': ['channel_role']}}}}}}}
        second_id = create('second', second)
        effective('peers-published')
        first['@@assign'] = None
        del first['ChatBot']['Platforms']['Slack']['Overrides'][workspace]['Supported_Channel_Types']
        observe('update-first', 'UpdatePolicy', {'PolicyId': first_id, 'Content': json.dumps(first)})
        effective('update-published')
        observe('detach-second', 'DetachPolicy', {'PolicyId': second_id, 'TargetId': member})
        attached.remove(second_id)
        effective('detach-published')
        observe('empty-fragment-update', 'UpdatePolicy', {'PolicyId': first_id, 'Content': '{"ChatBot":{}}'})
        effective('empty-fragment-published')
        empty_override = {'chatbot': {'platforms': {'slack': {'overrides': {workspace: {}}}}}}
        observe('empty-override-update', 'UpdatePolicy', {'PolicyId': first_id, 'Content': json.dumps(empty_override)})
        effective('empty-override-published')
        observe('validation-report', 'ListEffectivePolicyValidationErrors', {'AccountId': member, 'PolicyType': 'CHATBOT_POLICY'})
    finally:
        for policy in reversed(attached): required('DetachPolicy', {'PolicyId': policy, 'TargetId': member})
        for policy in reversed(owned): required('DeletePolicy', {'PolicyId': policy})
        if enabled: required('DisablePolicyType', {'RootId': root['Id'], 'PolicyType': 'CHATBOT_POLICY'})
        if required('ListRoots', {})['Roots'][0]['PolicyTypes'] != root['PolicyTypes']: raise RuntimeError('Policy type restoration failed')
        if sorted(a['Id'] for a in required('ListAccounts', {})['Accounts']) != sorted(a['Id'] for a in accounts): raise RuntimeError('Organization membership changed')
        if required('ListAWSServiceAccessForOrganization', {})['EnabledServicePrincipals'] != trusted: raise RuntimeError('Trusted service access changed')
        capture['cleanup'] = True
        save()
        print('cleanup: True', flush=True)


if __name__ == '__main__': main()
