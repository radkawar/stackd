#!/usr/bin/env python3
"""Capture inherited tag size and backup cross-field diagnostics.

Owned policies only, no account moves, and Backup trusted access must be disabled.
Backup plans use a nonexistent vault/role and a unique nonmatching resource tag.
"""
import copy
import datetime
import json
from pathlib import Path
import time
import uuid

from organizations_inputs_probe import call, required, probe_parser, verified_account, capture_path
from organizations_backup_policy_probe import assign


def main(account, output=None, details=False, inheritance=False, copies=False):
    owner = verified_account(account)
    root = required('ListRoots', {})['Roots'][0]
    organization = required('DescribeOrganization', {})['Organization']
    accounts = required('ListAccounts', {})['Accounts']
    services = required('ListAWSServiceAccessForOrganization', {})
    member = next(a['Id'] for a in accounts if a['Id'] != owner and a['State'] == 'ACTIVE')
    if any(p['Type'] in ['TAG_POLICY','BACKUP_POLICY'] for p in root['PolicyTypes']): raise RuntimeError('Requires disabled policy types')
    if any(s['ServicePrincipal']=='backup.amazonaws.com' for s in services.get('EnabledServicePrincipals',[])): raise RuntimeError('Requires Backup trusted access disabled')
    prefix='stackd-policy-limits-'+uuid.uuid4().hex[:10]
    result={'retrieved_at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'scope':'Owned tag size and inactive backup configuration; no account moves','observations':[],'cleanup':False}
    filename='organizations_backup_copy_duplicates' if copies=='duplicates' else 'organizations_backup_copy_inheritance' if copies else 'organizations_backup_inheritance' if inheritance else 'organizations_policy_limit_details' if details else 'organizations_policy_limits'
    path = capture_path(output or Path('.stackd/probes/iam') / (filename + '.json'))
    replacements={owner:'111111111111',member:'222222222222',root['Id']:'r-example',organization['Id']:'o-exampleorgid',prefix:'stackd-policy-limits-owned'}
    policies=[]
    attachments=[]
    enabled=[]
    def save():
        text=json.dumps(result,indent=2)
        for actual,label in replacements.items(): text=text.replace(actual,label)
        path.write_text(text+'\n')
    def observe(label, action, parameters):
        response=call(action,parameters)
        result['observations'].append(dict(case=label,action=action,input=parameters,**response))
        save()
        print(label+': '+response['code'],flush=True)
        return response
    def report(label,kind):
        time.sleep(20 if copies else 4)
        observe(label,'ListEffectivePolicyValidationErrors',{'AccountId':member,'PolicyType':kind})
        if copies:
            observe(label+'-effective','DescribeEffectivePolicy',{'TargetId':member,'PolicyType':kind})
    def create(label,kind,document,target=member):
        response=observe(label,'CreatePolicy',{'Name':prefix+'-'+label,'Description':'Owned policy limits capture','Type':kind,'Content':json.dumps(document,separators=(',',':'))})
        if response['code']!='Success': raise RuntimeError('Owned policy creation failed')
        policy=response['output']['Policy']['PolicySummary']['Id']
        policies.append(policy)
        replacements[policy]='POLICY_'+str(len(policies))
        response=observe(label+'-attach','AttachPolicy',{'PolicyId':policy,'TargetId':target})
        if response['code']!='Success': raise RuntimeError('Owned policy attachment failed')
        attachments.append((policy,target))
        return policy
    try:
        for kind in (['BACKUP_POLICY'] if details or inheritance else ['TAG_POLICY','BACKUP_POLICY']):
            response=observe('enable-'+kind,'EnablePolicyType',{'RootId':root['Id'],'PolicyType':kind})
            if response['code']!='Success': raise RuntimeError('Enable failed')
            enabled.append(kind)
        for index in range(0 if details or inheritance else 10):
            create('size-'+str(index),'TAG_POLICY',{'tags':{f'{i:05d}':{} for i in range(index*900,(index+1)*900)}})
            if index in [8,9]: report('size-'+str(index)+'-report','TAG_POLICY')
        document={'plans':{prefix:{'regions':assign(['us-east-1']),'rules':{'daily':{'target_backup_vault_name':assign(prefix)}},'selections':{'tags':{'selection':{'iam_role_arn':assign('arn:aws:iam::$account:role/'+prefix),'tag_key':assign(prefix),'tag_value':assign(['never-match-'+prefix])}}}}}}
        policy=create('backup-base','BACKUP_POLICY',document,root['Id'] if inheritance else member)
        report('backup-base-report','BACKUP_POLICY')
        if inheritance:
            empty={'plans':{prefix:{}}}
            child=create('backup-child','BACKUP_POLICY',empty)
            continuous={'enable_continuous_backup':assign('true'),'lifecycle':{'delete_after_days':assign('35')}}
            archive={'schedule_expression':assign('cron(0 5 1 * ? *)'),'lifecycle':{'move_to_cold_storage_after_days':assign('30'),'delete_after_days':assign('120'),'opt_in_to_archive_for_supported_resources':assign('true')}}
            scenarios=[
                ('continuous-long-retention',continuous,{'lifecycle':{'delete_after_days':assign('45')}}),
                ('continuous-cold',continuous,{'lifecycle':{'move_to_cold_storage_after_days':assign('1')}}),
                ('archive-daily',archive,{'schedule_expression':assign('cron(0 5 ? * * *)')}),
                ('archive-short-retention',archive,{'lifecycle':{'delete_after_days':assign('60')}}),
                ('archive-late-transition',archive,{'lifecycle':{'move_to_cold_storage_after_days':assign('90')}}),
                ('empty-index',{'index_actions':{'resource_types':assign(['EBS'])}},{'index_actions':{'resource_types':{'@@remove':['EBS']}}}),
            ]
            if copies:
                vault='arn:aws:backup:us-east-1:$account:backup-vault:'+prefix
                copy_rule={'schedule_expression':assign('cron(0 5 1 * ? *)'),'copy_actions':{vault:{'target_backup_vault_arn':assign(vault),'lifecycle':copy.deepcopy(archive['lifecycle'])}}}
                scenarios=[]
                for label,fields in [
                    ('copy-archive-daily',{'schedule_expression':assign('cron(0 5 ? * * *)')}),
                    ('copy-archive-short-retention',{'copy_actions':{vault:{'target_backup_vault_arn':assign(vault),'lifecycle':{'delete_after_days':assign('60')}}}}),
                    ('copy-archive-both',{'schedule_expression':assign('cron(0 5 ? * * *)'),'copy_actions':{vault:{'target_backup_vault_arn':assign(vault),'lifecycle':{'delete_after_days':assign('60')}}}}),
                    ('copy-archive-repaired',{'schedule_expression':assign('cron(0 5 1 JAN ? *)')}),
                ]:
                    scenarios.append((label,copy_rule,fields))
                if copies=='duplicates':
                    second=vault+'-second'
                    duplicate_rule=copy.deepcopy(copy_rule)
                    duplicate_rule['copy_actions'][second]=copy.deepcopy(duplicate_rule['copy_actions'][vault])
                    duplicate_rule['copy_actions'][second]['target_backup_vault_arn']=assign(second)
                    scenarios=[('copy-identical-errors',duplicate_rule,{'schedule_expression':assign('cron(0 5 ? * * *)')})]
            for label,parent_fields,child_fields in scenarios:
                observe(label+'-reset','UpdatePolicy',{'PolicyId':child,'Content':json.dumps(empty)})
                changed=copy.deepcopy(document)
                changed['plans'][prefix]['rules']['daily'].update(parent_fields)
                response=observe(label+'-parent','UpdatePolicy',{'PolicyId':policy,'Content':json.dumps(changed)})
                if response['code']!='Success': raise RuntimeError('Parent policy admission failed')
                report(label+'-parent-report','BACKUP_POLICY')
                fragment={'plans':{prefix:{'rules':{'daily':child_fields}}}}
                response=observe(label+'-child','UpdatePolicy',{'PolicyId':child,'Content':json.dumps(fragment)})
                if response['code']=='Success': report(label+'-child-report','BACKUP_POLICY')
            return
        cases=[]
        for label,update in [
            ('cold-short',{'lifecycle':{'move_to_cold_storage_after_days':assign('30'),'delete_after_days':assign('60')}}),
            ('cold-long',{'lifecycle':{'move_to_cold_storage_after_days':assign('30'),'delete_after_days':assign('120')}}),
            ('complete-shorter',{'start_backup_window_minutes':assign('120'),'complete_backup_window_minutes':assign('60')}),
            ('continuous-cold',{'enable_continuous_backup':assign('true'),'lifecycle':{'move_to_cold_storage_after_days':assign('1'),'delete_after_days':assign('30')}}),
            ('scan-no-settings',{'scan_actions':{'GUARDDUTY':{'scan_mode':assign('FULL_SCAN')}}}),
            ('copy-empty',{'copy_actions':{'arn:aws:backup:us-east-1:$account:backup-vault:Missing':{}}}),
            ('copy-short',{'copy_actions':{'arn:aws:backup:us-east-1:$account:backup-vault:Missing':{'target_backup_vault_arn':assign('arn:aws:backup:us-east-1:$account:backup-vault:Missing'),'lifecycle':{'move_to_cold_storage_after_days':assign('30'),'delete_after_days':assign('60')}}}}),
        ]:
            changed=copy.deepcopy(document)
            changed['plans'][prefix]['rules']['daily'].update(update)
            cases.append((label,changed))
        changed=copy.deepcopy(document)
        changed['plans'][prefix]['rules']={str(i):{'target_backup_vault_name':assign(prefix)} for i in range(11)}
        cases.append(('eleven-rules',changed))
        changed=copy.deepcopy(document)
        changed['plans'][prefix]['regions']={'@@remove':['us-east-1']}
        cases.append(('regions-removed',changed))
        changed=copy.deepcopy(document)
        changed['plans'][prefix]['selections']['resources']={'all':{'iam_role_arn':assign('arn:aws:iam::$account:role/'+prefix),'resource_types':assign(['*'])}}
        cases.append(('mixed-selections',changed))
        if details:
            cases=[]
            for label, fields in [
                ('empty-regions',{'regions':assign([])}),
                ('resource-condition-only',{'selections':{'resources':{'all':{'iam_role_arn':assign('arn:aws:iam::$account:role/'+prefix),'conditions':{'string_equals':{'tag':{'condition_key':assign('aws:ResourceTag/'+prefix),'condition_value':assign(prefix)}}}}}}}),
                ('scanner-role-only',{'scan_settings':{'GUARDDUTY':{'scanner_role_arn':assign('arn:aws:iam::$account:role/'+prefix)}}}),
                ('scan-settings-no-actions',{'scan_settings':{'GUARDDUTY':{'scanner_role_arn':assign('arn:aws:iam::$account:role/'+prefix),'resource_types':assign(['EBS'])}}}),
            ]:
                changed=copy.deepcopy(document)
                changed['plans'][prefix].update(fields)
                cases.append((label,changed))
            for label,value in [('removed-tag-values',{'@@remove':['one']}),('empty-tag-values',{'@@append':[]})]:
                changed=copy.deepcopy(document)
                changed['plans'][prefix]['selections']['tags']['selection']['tag_value']=value
                cases.append((label,changed))
        for label,changed in cases:
            response=observe(label,'UpdatePolicy',{'PolicyId':policy,'Content':json.dumps(changed,separators=(',',':'))})
            if response['code']=='Success': report(label+'-report','BACKUP_POLICY')
    finally:
        failures=[]
        for policy,target in reversed(attachments):
            response=call('DetachPolicy',{'PolicyId':policy,'TargetId':target})
            if response['code'] not in ['Success','PolicyNotAttachedException']: failures.append(response)
        for policy in reversed(policies):
            response=call('DeletePolicy',{'PolicyId':policy})
            if response['code']!='Success': failures.append(response)
        for kind in reversed(enabled):
            response=call('DisablePolicyType',{'RootId':root['Id'],'PolicyType':kind})
            if response['code']!='Success': failures.append(response)
        result['cleanup']=not failures and required('ListRoots',{})['Roots'][0]==root
        result['memberships_unchanged']=sorted((a['Id'],a['State']) for a in accounts)==sorted((a['Id'],a['State']) for a in required('ListAccounts',{})['Accounts'])
        result['trusted_services_unchanged']=required('ListAWSServiceAccessForOrganization',{})==services
        result['cleanup_failures']=failures
        save()
        print('cleanup: '+str(result['cleanup']),flush=True)
        if not all(result[k] for k in ['cleanup','memberships_unchanged','trusted_services_unchanged']): raise RuntimeError('Original organization state was not restored')


if __name__=='__main__':
    parser = probe_parser()
    parser.add_argument('--details', action='store_true')
    parser.add_argument('--inheritance', action='store_true')
    parser.add_argument('--copies', action='store_true')
    parser.add_argument('--copy-duplicates', action='store_true')
    args = parser.parse_args()
    copies = 'duplicates' if args.copy_duplicates else args.copies
    main(args.account, args.output, details=args.details, inheritance=args.inheritance or copies, copies=copies)
