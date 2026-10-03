#!/usr/bin/env python3
"""Capture management-policy validation using owned policies.

No account is moved. Backup trusted access must remain disabled; configured plans
use nonexistent uniquely named vaults/roles and nonmatching resource tags.
"""
import datetime
import json
import time
import uuid

from organizations_inputs_probe import call, required, probe_parser, verified_account, capture_path


def main():
    args = probe_parser('organizations_policy_validation.json').parse_args()
    owner = verified_account(args.account)
    root = required('ListRoots', {})['Roots'][0]
    organization = required('DescribeOrganization', {})['Organization']
    accounts = required('ListAccounts', {})['Accounts']
    member = next(a['Id'] for a in accounts if a['Id'] != owner and a['State'] == 'ACTIVE')
    services = required('ListAWSServiceAccessForOrganization', {})
    if organization['FeatureSet'] != 'ALL' or any(p['Type'] in ['TAG_POLICY','BACKUP_POLICY'] for p in root['PolicyTypes']):
        raise RuntimeError('Requires ALL with TAG_POLICY and BACKUP_POLICY disabled')
    prefix = 'stackd-validation-' + uuid.uuid4().hex[:10]
    capture = {'retrieved_at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'scope':'Owned non-enforcing tag and inactive backup policies; no account moves','observations':[], 'cleanup':False}
    replacements = {owner:'111111111111',member:'222222222222',root['Id']:'r-example',organization['Id']:'o-exampleorgid',prefix:'stackd-validation-owned'}
    path = capture_path(args.output)
    def save():
        text = json.dumps(capture,indent=2)
        for actual,label in replacements.items(): text=text.replace(actual,label)
        path.write_text(text+'\n')
    def observe(label, action, parameters):
        result = call(action, parameters)
        capture['observations'].append(dict(case=label,action=action,input=parameters,**result))
        save()
        print(label+': '+result['code'],flush=True)
        return result
    def report(label,kind):
        # Capture both the report and the separately readable effective document.
        time.sleep(4)
        observe(label, 'ListEffectivePolicyValidationErrors', {'AccountId':member,'PolicyType':kind})
        observe(label+'-effective', 'DescribeEffectivePolicy', {'TargetId':member,'PolicyType':kind})
    policies=[]
    attached=[]
    enabled=[]
    def create(label,kind,content,target):
        result=observe(label,'CreatePolicy',{'Name':prefix+'-'+label,'Description':'Owned policy validation capture','Type':kind,'Content':json.dumps(content)})
        if result['code']!='Success': return None
        policy=result['output']['Policy']['PolicySummary']['Id']
        policies.append(policy)
        replacements[policy]='POLICY_'+str(len(policies))
        if target:
            attached_result=observe(label+'-attach','AttachPolicy',{'PolicyId':policy,'TargetId':target})
            if attached_result['code']!='Success': raise RuntimeError('Could not attach owned policy')
            attached.append((policy,target,kind))
            observe(label+'-attached','ListEffectivePolicyValidationErrors',{'AccountId':member,'PolicyType':kind})
        return policy
    try:
        for label,params in [
            ('disabled-tag',{'AccountId':owner,'PolicyType':'TAG_POLICY'}),
            ('disabled-backup',{'AccountId':owner,'PolicyType':'BACKUP_POLICY'}),
            ('unknown-account',{'AccountId':'999999999999','PolicyType':'TAG_POLICY'}),
            ('missing-account',{'PolicyType':'TAG_POLICY'}),
            ('root-target',{'AccountId':root['Id'],'PolicyType':'TAG_POLICY'}),
            ('missing-type',{'AccountId':owner}),
            ('scp-type',{'AccountId':owner,'PolicyType':'SERVICE_CONTROL_POLICY'}),
            ('rcp-type',{'AccountId':owner,'PolicyType':'RESOURCE_CONTROL_POLICY'}),
            ('invalid-type',{'AccountId':owner,'PolicyType':'WRONG'})]:
            observe(label,'ListEffectivePolicyValidationErrors',params)
        result=observe('enable-tag','EnablePolicyType',{'RootId':root['Id'],'PolicyType':'TAG_POLICY'})
        if result['code']!='Success': raise RuntimeError('Could not enable tag policies')
        enabled.append('TAG_POLICY')
        report('tag-empty','TAG_POLICY')
        create('tag-values','TAG_POLICY',{'tags':{prefix:{'tag_value':{'@@assign':['one']}}}},root['Id'])
        create('tag-remove','TAG_POLICY',{'tags':{prefix:{'tag_value':{'@@remove':['one']}}}},member)
        report('tag-no-values','TAG_POLICY')
        required_policies=[]
        for label,start,stop,target in [('tag-required-root',0,30,root['Id']),('tag-required-member',30,55,member)]:
            content={'tags':{prefix+'-'+str(i):{'report_required_tag_for':{'@@assign':['ec2:instance']}} for i in range(start,stop)}}
            policy=create(label,'TAG_POLICY',content,target)
            if policy: required_policies.append((policy,target,'TAG_POLICY'))
            report(label+'-report','TAG_POLICY')
        for policy,target,kind in required_policies:
            result=observe('tag-required-detach','DetachPolicy',{'PolicyId':policy,'TargetId':target})
            if result['code']!='Success': raise RuntimeError('Could not detach owned required-tag policy')
            attached.remove((policy,target,kind))
        report('tag-required-cleared','TAG_POLICY')
        op=observe('enable-backup','EnablePolicyType',{'RootId':root['Id'],'PolicyType':'BACKUP_POLICY'})
        if op['code']=='Success':
            enabled.append('BACKUP_POLICY')
            report('backup-empty','BACKUP_POLICY')
            create('backup-empty-plan','BACKUP_POLICY',{'plans':{'daily':{}}},member)
            report('backup-incomplete','BACKUP_POLICY')
            create('backup-rules','BACKUP_POLICY',{'plans':{'daily':{'rules':{'daily':{'start_backup_window_minutes':{'@@assign':'60'}}}}}},root['Id'])
            report('backup-inherited-incomplete','BACKUP_POLICY')
            for label, content in [
                ('backup-partial-region',{'plans':{'daily':{'regions':{'@@assign':['us-east-1']}}}}),
                ('backup-empty-selections',{'plans':{'daily':{'selections':{'tags':{}}}}}),
                ('backup-lifecycle',{'plans':{'daily':{'rules':{'daily':{'lifecycle':{'move_to_cold_storage_after_days':{'@@assign':'30'},'delete_after_days':{'@@assign':'60'}}}}}}}),
            ]:
                create(label,'BACKUP_POLICY',content,None)
            create('backup-incomplete-rule','BACKUP_POLICY',{'plans':{'daily':{'rules':{'weekly':{'target_backup_vault_name':{'@@assign':'validation-vault'}}}}}},member)
            time.sleep(20)
            report('backup-later','BACKUP_POLICY')
            for label,params in [('max-one',{'MaxResults':1}),('bad-token',{'NextToken':'invalid'}),('empty-token',{'NextToken':''}),('zero-limit',{'MaxResults':0}),('large-limit',{'MaxResults':21})]:
                observe(label,'ListEffectivePolicyValidationErrors',dict(AccountId=member,PolicyType='BACKUP_POLICY',**params))
        if any(p['ServicePrincipal']=='backup.amazonaws.com' for p in required('ListAWSServiceAccessForOrganization',{}).get('EnabledServicePrincipals',[])):
            raise RuntimeError('Backup execution must remain disabled for this capture')
        from organizations_backup_policy_probe import assign
        document={'plans':{prefix:{'regions':assign(['us-east-1']),'rules':{'daily':{'target_backup_vault_name':assign(prefix)}},'selections':{'tags':{'cost':{'iam_role_arn':assign('arn:aws:iam::$account:role/'+prefix),'tag_key':assign(prefix),'tag_value':assign(['never-match-'+prefix])}}}}}}
        valid=create('backup-configured','BACKUP_POLICY',document,member)
        report('backup-configured-view','BACKUP_POLICY')
        for policy,target,kind in list(attached):
            if kind == 'BACKUP_POLICY' and policy != valid:
                result=observe('backup-isolate-detach','DetachPolicy',{'PolicyId':policy,'TargetId':target})
                if result['code']!='Success': raise RuntimeError('Could not detach owned policy')
                attached.remove((policy,target,kind))
        report('backup-configured-alone','BACKUP_POLICY')
        if valid:
            del document['plans'][prefix]['selections']
            observe('backup-configured-invalidated','UpdatePolicy',{'PolicyId':valid,'Content':json.dumps(document)})
            report('backup-configured-invalid','BACKUP_POLICY')
        for policy,target,kind in list(attached):
            if kind == 'BACKUP_POLICY':
                result=observe('backup-clear-detach','DetachPolicy', {'PolicyId':policy,'TargetId':target})
                if result['code']!='Success': raise RuntimeError('Could not detach owned policy')
                attached.remove((policy,target,kind))
        report('backup-cleared','BACKUP_POLICY')
    finally:
        failures=[]
        for policy,target,kind in reversed(attached):
            result=call('DetachPolicy',{'PolicyId':policy,'TargetId':target})
            if result['code'] not in ['Success','PolicyNotAttachedException']: failures.append(result)
        for policy in reversed(policies):
            result=call('DeletePolicy',{'PolicyId':policy})
            if result['code']!='Success': failures.append(result)
        for kind in reversed(enabled):
            result=call('DisablePolicyType',{'RootId':root['Id'],'PolicyType':kind})
            if result['code']!='Success': failures.append(result)
        capture['cleanup']=not failures and required('ListRoots',{})['Roots'][0]==root
        capture['memberships_unchanged']=sorted((a['Id'],a['State']) for a in accounts)==sorted((a['Id'],a['State']) for a in required('ListAccounts',{})['Accounts'])
        capture['trusted_services_unchanged']=required('ListAWSServiceAccessForOrganization',{})==services
        capture['cleanup_failures']=failures
        save()
        print('cleanup: '+str(capture['cleanup']),flush=True)
        if not all(capture[k] for k in ['cleanup','memberships_unchanged','trusted_services_unchanged']): raise RuntimeError('Original organization state was not restored')

if __name__=='__main__': main()
