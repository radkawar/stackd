#!/usr/bin/env python3
"""Capture backup policy admission without attaching policies or enabling backup."""
import json

from organizations_policy_admission_probe import capture, probe_parser


def plan(**settings): return {'plans': {'daily': settings}}
def rule(**settings): return plan(rules={'daily': settings})
def assign(value): return {'@@assign': value}


def cases():
    yield 'empty-document', {}
    yield 'empty-plans', {'plans':{}}
    yield 'empty-plan', plan()
    yield 'unknown-root', {'other':{}}
    yield 'unknown-plan-field', plan(other=assign('one'))
    yield 'unknown-rule-field', rule(other=assign('one'))
    yield 'container-assign', {'plans':assign({})}
    yield 'container-controls', {'plans':{'@@operators_allowed_for_child_policies':['@@none']}}
    for name in ['with space','with.dot','A_-9','é','x'*50,'x'*51]:
        yield 'plan-name-'+str(len(name))+'-'+name[:10], {'plans':{name:{'regions':assign(['us-east-1'])}}}
    for value in [[],['us-east-1'],['wrong'],['*'],'us-east-1',[12],['us-east-1','us-east-1']]:
        yield 'regions-'+json.dumps(value), plan(regions=assign(value))
    yield 'regions-append', plan(regions={'@@append':['us-east-1']})
    yield 'regions-remove', plan(regions={'@@remove':['us-east-1']})
    yield 'region-both-operators', plan(regions={'@@assign':['us-east-1'],'@@append':['us-west-2']})
    for field in ['start_backup_window_minutes','complete_backup_window_minutes']:
        for value in ['0','1','30','59','60','10080','52560000','60.5',60,True,'bad']:
            yield field+'-'+json.dumps(value), rule(**{field:assign(value)})
    for value in ['cron(0 5 ? * * *)','bad','rate(1 day)','cron(* * * * * *)','']:
        yield 'schedule-'+value, rule(schedule_expression=assign(value))
    for value in [True,False,'true','false','TRUE',1,'yes']:
        yield 'continuous-'+json.dumps(value), rule(enable_continuous_backup=assign(value))
    for value in ['vault','with space','with.dot','a','x'*50,'x'*51,'']:
        yield 'vault-'+str(len(value))+'-'+value[:10], rule(target_backup_vault_name=assign(value))
    for value in ['-1','0','1','36500','36501',1,'bad']:
        yield 'cold-'+json.dumps(value), rule(lifecycle={'move_to_cold_storage_after_days':assign(value)})
        yield 'delete-'+json.dumps(value), rule(lifecycle={'delete_after_days':assign(value)})
    yield 'lifecycle-relationship', rule(lifecycle={'move_to_cold_storage_after_days':assign('30'),'delete_after_days':assign('60')})
    yield 'empty-tags-selection', plan(selections={'tags':{}})
    yield 'empty-tag-selection', plan(selections={'tags':{'selection':{}}})
    for value in [[],['one'],'one',[1]]:
        yield 'selection-values-'+json.dumps(value), plan(selections={'tags':{'selection':{'tag_value':assign(value)}}})
    for value in ['arn:aws:iam::$account:role/Test','arn:aws:iam::111111111111:role/Test','bad']:
        yield 'selection-role-'+value, plan(selections={'tags':{'selection':{'iam_role_arn':assign(value)}}})
    for value in [['arn:aws:ec2:*:*:volume/*'],['arn:aws:sqs:*:*:*'],['*'],[]]:
        yield 'selection-resources-'+json.dumps(value), plan(selections={'resources':{'selection':{'resource_types':assign(value)}}})

    for field in ['start_backup_window_minutes','complete_backup_window_minutes']:
        for value in [60.0,'060','+60',' 60','1e2','9223372036854775807','9223372036854775808']:
            yield field+'-extended-'+json.dumps(value), rule(**{field:assign(value)})
    for value in [True,'true','false']:
        for days in ['35','36']:
            yield 'continuous-retention-'+str(value)+'-'+days, rule(enable_continuous_backup=assign(value),lifecycle={'delete_after_days':assign(days)})
    for value in [[],['one'],'one',[1]]:
        yield 'selection-values-'+json.dumps(value), plan(selections={'tags':{'selection':{'tag_value':assign(value)}}})
    yield 'scalar-append', rule(target_backup_vault_name={'@@append':['vault']})
    yield 'scalar-remove', rule(target_backup_vault_name={'@@remove':['vault']})
    yield 'unknown-lifecycle', rule(lifecycle={'other':assign('1')})
    yield 'rules-count-11', plan(rules={str(i):{'target_backup_vault_name':assign('vault')} for i in range(11)})
    yield 'rules-count-10', plan(rules={str(i):{'target_backup_vault_name':assign('vault')} for i in range(10)})
    for resource,field in [('ec2','windows_vss'),('s3','backup_acls'),('s3','backup_object_tags')]:
        for value in ['enabled','disabled','wrong',True]:
            yield 'advanced-'+resource+'-'+field+'-'+str(value), plan(advanced_backup_settings={resource:{field:assign(value)}})
    yield 'advanced-other', plan(advanced_backup_settings={'other':{'field':assign('enabled')}})
    for value in [True,False,'true','false','enabled']:
        yield 'archive-'+str(value), rule(lifecycle={'opt_in_to_archive_for_supported_resources':assign(value)})
    for value in [['EBS'],['S3'],['EBS','S3'],['WRONG'],[]]:
        yield 'index-'+json.dumps(value), rule(index_actions={'resource_types':assign(value)})
    for value in ['x','aws:reserved','',12]:
        yield 'plan-tag-key-'+str(value), plan(backup_plan_tags={'cost':{'tag_key':assign(value),'tag_value':assign('one')}})


if __name__ == '__main__':
    args = probe_parser('organizations_backup_policy.json').parse_args()
    capture(cases(), args.output, 'BACKUP_POLICY', args.account)
