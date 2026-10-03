#!/usr/bin/env python3
"""Capture management-policy inheritance with temporary, non-enforcing tag policies.

Requires the designated ALL organization with tag policies disabled. Existing
accounts keep their memberships; only uniquely named policies are attached, and
TAG_POLICY is disabled again after detaching and deleting all owned policies.
"""
import datetime
import json
import time
import uuid

from organizations_inputs_probe import call, required, probe_parser, verified_account, capture_path
from organizations_resource_policy_probe import cli, org_call


def main():
    args = probe_parser('organizations_effective_policy.json').parse_args()
    owner = verified_account(args.account)
    organization = required('DescribeOrganization', {})['Organization']
    root = required('ListRoots', {})['Roots'][0]
    if organization['FeatureSet'] != 'ALL' or any(p['Type'] == 'TAG_POLICY' for p in root['PolicyTypes']):
        raise RuntimeError('Requires ALL with TAG_POLICY disabled')
    accounts = required('ListAccounts', {})['Accounts']
    member = next(a['Id'] for a in accounts if a['Id'] != owner and a['State'] == 'ACTIVE' and a['JoinedMethod'] == 'CREATED')
    credentials = cli('sts', 'assume-role', {'RoleArn': 'arn:aws:iam::'+member+':role/OrganizationAccountAccessRole', 'RoleSessionName': 'stackd-effective-policy', 'DurationSeconds': 3600})['Credentials']
    prefix = 'stackd-effective-' + uuid.uuid4().hex[:10]
    replacements = {owner: '111111111111', member: '222222222222', root['Id']: 'r-example', organization['Id']: 'o-exampleorgid', prefix: 'stackd-effective-owned'}
    capture = {'retrieved_at': datetime.datetime.now(datetime.timezone.utc).isoformat(), 'scope': 'Owned non-enforcing tag policies; no account moves or compute resources', 'observations': [], 'cleanup': False}
    path = capture_path(args.output)
    def save():
        text = json.dumps(capture, indent=2)
        for actual, label in sorted(replacements.items(), key=lambda item: -len(item[0])): text = text.replace(actual, label)
        path.write_text(text+'\n')
    def observe(name, action, params, actor=None):
        result = org_call(action, params, actor)
        capture['observations'].append(dict(case=name, action=action, input=params, actor='member' if actor else 'management', **result))
        save()
        print(name+': '+result['code'], flush=True)
        return result
    def effective(name, actor=None, target=member):
        params = {'PolicyType': 'TAG_POLICY'}
        if target is not None: params['TargetId'] = target
        return observe(name, 'DescribeEffectivePolicy', params, actor)
    def settle(name):
        previous = None
        prior = next((r['output']['EffectivePolicy']['LastUpdatedTimestamp'] for r in reversed(capture['observations']) if r.get('output',{}).get('EffectivePolicy',{}).get('TargetId') == member), None)
        polls = []
        start = time.monotonic()
        for attempt in range(20):
            result = org_call('DescribeEffectivePolicy', {'PolicyType':'TAG_POLICY','TargetId':member})
            value = result.get('output',{}).get('EffectivePolicy',{})
            signature = (result['code'], value.get('PolicyContent'), value.get('LastUpdatedTimestamp'))
            polls.append({'elapsed_seconds':round(time.monotonic()-start,3),'code':result['code'],'last_updated':value.get('LastUpdatedTimestamp')})
            if previous == signature and attempt >= 2 and signature[2] != prior: break
            previous = signature
            time.sleep(2)
        result = effective(name)
        capture['observations'][-1]['generation_polls'] = polls
        save()
        return result
    owned, attached = [], []
    enabled = False
    try:
        for name, target, actor in [('disabled-member',member,None),('disabled-own',None,None),('disabled-root',root['Id'],None),('disabled-unknown','123456789012',None),('member-own',None,credentials),('member-explicit-own',member,credentials),('member-other',owner,credentials)]:
            effective(name,actor,target)
        for kind in ['SERVICE_CONTROL_POLICY','RESOURCE_CONTROL_POLICY','wrong']:
            observe('invalid-kind-'+kind,'DescribeEffectivePolicy',{'PolicyType':kind})
        observe('missing-kind','DescribeEffectivePolicy',{})
        required('EnablePolicyType', {'RootId':root['Id'],'PolicyType':'TAG_POLICY'})
        enabled = True
        settle('enabled-empty')
        effective('enabled-management',target=None)
        documents = [{'tags':{}},{'tags':{}},{'tags':{}}]
        scenarios = {
            'replace': ({'@@assign':['red','blue']},None,{'@@assign':['green']}),
            'append': ({'@@assign':['red','blue']},None,{'@@append':['blue','green']}),
            'remove': ({'@@assign':['red','blue']},None,{'@@remove':['red','missing']}),
            'lock': ({'@@assign':['red'],'@@operators_allowed_for_child_policies':['@@none']},None,{'@@assign':['green']}),
            'append_only': ({'@@assign':['red'],'@@operators_allowed_for_child_policies':['@@append']},None,{'@@append':['green']}),
            'cannot_unlock': ({'@@assign':['red'],'@@operators_allowed_for_child_policies':['@@append']},None,{'@@assign':['green'],'@@operators_allowed_for_child_policies':['@@all']}),
            'same_assign': ({'@@assign':['red']},{'@@assign':['blue']},None),
            'same_assign_lists': ({'@@assign':['red','blue']},{'@@assign':['blue','green']},None),
            'same_remove': ({'@@assign':['red','blue']},{'@@remove':['red']},None),
            'same_append_remove': ({'@@append':['red']},{'@@remove':['red']},None),
            'same_remove_append': ({'@@remove':['red']},{'@@append':['red']},None),
            'multi_operators': ({'@@assign':['red'],'@@append':['blue'],'@@remove':['red']},None,None),
            'child_multi_operators': ({'@@assign':['red','blue']},None,{'@@assign':['green'],'@@append':['yellow'],'@@remove':['green']}),
            'same_append': ({'@@append':['red']},{'@@append':['blue']},None),
            'same_assign_append': ({'@@assign':['red']},{'@@append':['blue']},None),
            'same_append_assign': ({'@@append':['red']},{'@@assign':['blue']},None),
            'intersection': ({'@@assign':['red'],'@@operators_allowed_for_child_policies':['@@append']},{'@@operators_allowed_for_child_policies':['@@remove']},{'@@append':['green']}),
            'empty_remove': ({'@@assign':['red']},None,{'@@remove':['red']}),
            'orphan_remove': (None,None,{'@@remove':['red']}),
        }
        for name, values in scenarios.items():
            key = prefix+'-'+name
            for doc, value in zip(documents, values):
                if value is not None: doc['tags'][key] = {'tag_key':{'@@assign':key},'tag_value':value}
        documents[0]['tags'][prefix+'-logical-lock'] = {'@@operators_allowed_for_child_policies':['@@none'],'tag_value':{'@@assign':['red']}}
        documents[2]['tags'][prefix+'-logical-lock'] = {'tag_value':{'@@assign':['blue']}}
        documents[0]['tags'][prefix+'-numeric'] = {'tag_value':{'@@assign':[12,True,None]}}
        documents[2]['tags'][prefix+'-numeric'] = {'tag_value':{'@@append':['12',13]}}
        documents[0]['tags'][prefix+'-Empty'] = {}
        documents[0]['tags'][prefix+'-Default'] = {'tag_value':{'@@assign':['red']}}
        documents[2]['tags'][prefix+'-default'] = {'tag_value':{'@@append':['blue']}}
        for index, document in enumerate(documents):
            params = {'Name':prefix+'-'+str(index), 'Description':'Owned non-enforcing inheritance probe', 'Type':'TAG_POLICY', 'Content':json.dumps(document)}
            result = observe('create-'+str(index),'CreatePolicy',params)
            if result['code'] != 'Success': raise RuntimeError('CreatePolicy: '+result['code'])
            policy = result['output']['Policy']['PolicySummary']['Id']
            owned.append(policy)
            replacements[policy] = 'POLICY_'+str(index)
            target = member if index == 2 else root['Id']
            required('AttachPolicy', {'PolicyId':policy,'TargetId':target})
            attached.append((policy,target))
            settle('attached-'+str(index))
        effective('member-effective',credentials,None)
        effective('member-explicit-effective',credentials,member)
        effective('member-other-effective',credentials,owner)
        resource = 'arn:aws:organizations::'+owner+':account/'+organization['Id']+'/'+member
        for label, resource_arn, condition in [('account-arn',resource,{}),('wrong-arn',resource.replace(member,owner),{}),('resource-owner',resource,{'StringEquals':{'aws:ResourceAccount':owner}}),('resource-member',resource,{'StringEquals':{'aws:ResourceAccount':member}}),('policy-type',resource,{'StringEquals':{'organizations:PolicyType':'TAG_POLICY'}})]:
            session_policy = {'Version':'2012-10-17','Statement':[{'Effect':'Allow','Action':'organizations:DescribeEffectivePolicy','Resource':resource_arn,'Condition':condition}]}
            actor = cli('sts','assume-role',{'RoleArn':'arn:aws:iam::'+member+':role/OrganizationAccountAccessRole','RoleSessionName':'stackd-effective-'+label,'DurationSeconds':900,'Policy':json.dumps(session_policy)})['Credentials']
            effective('session-'+label,actor,None)
        effective('root-effective',target=root['Id'])
        effective('unknown-effective',target='123456789012')
        effective('management-inherited',target=None)
        time.sleep(3)
        effective('unchanged-read')
        required('UpdatePolicy',{'PolicyId':owned[0],'Description':'Changed metadata only'})
        settle('metadata-update')
        required('UpdatePolicy',{'PolicyId':owned[0],'Content':json.dumps(documents[0])})
        settle('unchanged-content-update')
        required('DetachPolicy',{'PolicyId':owned[0],'TargetId':root['Id']})
        attached.remove((owned[0],root['Id']))
        settle('first-detached')
        required('AttachPolicy',{'PolicyId':owned[0],'TargetId':root['Id']})
        attached.append((owned[0],root['Id']))
        settle('first-reattached')
        for name, content in [('duplicate-case',{'tags':{'Key':{'tag_value':{'@@assign':['first']}},'key':{'tag_value':{'@@assign':['second']}}}}),('ecs-wildcard',{'tags':{'key':{'enforced_for':{'@@assign':['ecs:*']}}}}),('ecs-all',{'tags':{'key':{'enforced_for':{'@@assign':['ecs:ALL_SUPPORTED']}}}}),('sqs-resource',{'tags':{'key':{'enforced_for':{'@@assign':['sqs:queue']}}}}),('boolean-value',{'tags':{'key':{'tag_value':{'@@assign':[True]}}}}),('null-value',{'tags':{'key':{'tag_value':{'@@assign':[None]}}}}),('object-value',{'tags':{'key':{'tag_value':{'@@assign':[{'x':'y'}]}}}}),('empty-rule',{'tags':{'key':{}}}),('numeric-key',{'tags':{'key':{'tag_key':{'@@assign':12}}}}),('wrong-key',{'tags':{'key':{'tag_key':{'@@assign':'other'}}}}),('empty-key',{'tags':{'':{}}}),('numeric-value',{'tags':{'key':{'tag_value':{'@@assign':[12]}}}}),('many-wildcards',{'tags':{'key':{'tag_value':{'@@assign':['a*b*']}}}}),('unknown-resource',{'tags':{'key':{'enforced_for':{'@@assign':['imaginary:thing']}}}}),('container-control',{'tags':{'@@operators_allowed_for_child_policies':['@@none'],'key':{'tag_value':{'@@assign':['red']}}}}),('logical-control',{'tags':{'key':{'@@operators_allowed_for_child_policies':['@@none'],'tag_value':{'@@assign':['red']}}}}),('empty',{}),('empty-tags',{'tags':{}}),('wrong-root',{'wrong':{}}),('raw-value',{'tags':{'key':{'tag_key':'key'}}}),('unknown-field',{'tags':{'key':{'unknown':{'@@assign':'key'}}}}),('multi-operators',{'tags':{'key':{'tag_value':{'@@assign':['a'],'@@append':['b']}}}}),('scalar-append',{'tags':{'key':{'tag_key':{'@@append':['key']}}}}),('invalid-control',{'tags':{'key':{'tag_key':{'@@operators_allowed_for_child_policies':['@@wrong']}}}})]:
            params={'Name':prefix+'-validation','Description':'Owned validation probe','Type':'TAG_POLICY','Content':json.dumps(content)}
            result=observe('validation-'+name,'CreatePolicy',params)
            if result['code']=='Success':
                pid=result['output']['Policy']['PolicySummary']['Id']
                required('DeletePolicy',{'PolicyId':pid})
    finally:
        failures=[]
        for policy,target in reversed(attached):
            result=call('DetachPolicy',{'PolicyId':policy,'TargetId':target})
            if result['code'] not in ['Success','PolicyNotAttachedException']: failures.append(result)
        for policy in reversed(owned):
            result=call('DeletePolicy',{'PolicyId':policy})
            if result['code']!='Success': failures.append(result)
        if enabled:
            result=call('DisablePolicyType',{'RootId':root['Id'],'PolicyType':'TAG_POLICY'})
            if result['code']!='Success': failures.append(result)
        after=required('ListRoots',{})['Roots'][0]
        capture['cleanup']=not failures and after==root
        capture['memberships_unchanged']=sorted((a['Id'],a['State']) for a in accounts)==sorted((a['Id'],a['State']) for a in required('ListAccounts',{})['Accounts'])
        capture['cleanup_failures']=failures
        save()
        print('cleanup: '+str(capture['cleanup']),flush=True)
        if not capture['cleanup'] or not capture['memberships_unchanged']:
            raise RuntimeError('Owned probe did not restore its original organization state; inspect the capture')

if __name__ == '__main__': main()
