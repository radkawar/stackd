#!/usr/bin/env python3
"""Capture remaining backup selection, tag, lifecycle and scanning constraints."""
from organizations_backup_policy_probe import plan, rule, assign
from organizations_policy_admission_probe import capture, probe_parser


def cases():
    role='arn:aws:iam::$account:role/StackdValidationRole'
    fields={'iam_role_arn':assign(role),'tag_key':assign('cost'),'tag_value':assign(['one'])}
    for drop in [None,'iam_role_arn','tag_key','tag_value']:
        doc={k:v for k,v in fields.items() if k!=drop}
        yield 'tag-selection-without-'+str(drop), plan(selections={'tags':{'cost':doc}})
    for key in ['Cost','other','', 'x'*128, 'x'*129]:
        yield 'selection-key-'+str(len(key))+'-'+key[:10], plan(selections={'tags':{'cost':dict(fields,tag_key=assign(key))}})
    for value in [[],['one'],'one',[1],['']]:
        yield 'selection-values-'+str(value), plan(selections={'tags':{'cost':dict(fields,tag_value=assign(value))}})
    for value in [role,'arn:aws:iam::111111111111:role/Test','bad']:
        yield 'selection-role-'+value, plan(selections={'tags':{'cost':dict(fields,iam_role_arn=assign(value))}})
    yield 'selection-alias', plan(selections={'tags':{'other':fields}})
    yield 'resource-role-only', plan(selections={'resources':{'selection':{'iam_role_arn':assign(role)}}})
    for value in ['cost','Cost','other','',12]:
        yield 'plan-tag-key-'+str(value), plan(backup_plan_tags={'cost':{'tag_key':assign(value),'tag_value':assign('one')}})
    for value in ['one',['one'],'',12,True]:
        yield 'plan-tag-value-'+str(value), plan(backup_plan_tags={'cost':{'tag_key':assign('cost'),'tag_value':assign(value)}})
    yield 'plan-tag-no-key', plan(backup_plan_tags={'cost':{'tag_value':assign('one')}})
    yield 'plan-tag-no-value', plan(backup_plan_tags={'cost':{'tag_key':assign('cost')}})
    for value in ['2147483647','2147483648','999999999','1000000000']:
        yield 'integer-limit-'+value, rule(start_backup_window_minutes=assign(value))
    for cold in [None,'1','30']:
        for archive in ['true','false']:
            lifecycle={'opt_in_to_archive_for_supported_resources':assign(archive)}
            if cold: lifecycle['move_to_cold_storage_after_days']=assign(cold)
            yield 'archive-cold-'+str(cold)+'-'+archive, rule(lifecycle=lifecycle)
    for value in ['arn:aws:backup:us-east-1:$account:backup-vault:Vault','arn:aws:backup:$region:$account:backup-vault:Vault','bad']:
        yield 'copy-'+value, rule(copy_actions={value:{'target_backup_vault_arn':assign(value)}})
        yield 'air-gapped-'+value, rule(target_logically_air_gapped_backup_vault_arn=assign(value))
    for mode in ['INCREMENTAL_SCAN','FULL_SCAN','wrong']:
        yield 'scan-mode-'+mode, rule(scan_actions={'GUARDDUTY':{'scan_mode':assign(mode)}})
    for resources in [['EBS'],['EC2'],['S3'],['ALL'],['wrong'],[]]:
        yield 'scan-resources-'+str(resources), plan(scan_settings={'GUARDDUTY':{'resource_types':assign(resources),'scanner_role_arn':assign(role)}})
    yield 'condition-equals', plan(selections={'resources':{'selection':{'conditions':{'string_equals':{'condition1':{'condition_key':assign('aws:ResourceTag/cost'),'condition_value':assign('one')}}}}}})
    yield 'condition-missing-value', plan(selections={'resources':{'selection':{'conditions':{'string_equals':{'condition1':{'condition_key':assign('aws:ResourceTag/cost')}}}}}})

if __name__ == '__main__':
    args = probe_parser('organizations_backup_extended.json').parse_args()
    capture(cases(), args.output, 'BACKUP_POLICY', args.account)
