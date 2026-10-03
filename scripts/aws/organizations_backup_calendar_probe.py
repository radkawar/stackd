#!/usr/bin/env python3
"""Capture backup cron and archive calendars with unattached owned policies."""
from organizations_backup_policy_probe import rule, assign
from organizations_policy_admission_probe import capture, probe_parser
from pathlib import Path


def cases():
    for expression in [
        '0 5 1,29 JAN ? *', '0 5 1,29 * ? *',
        '0 5 1,29 FEB ? *', '0 5 1,28 FEB ? *',
        '0 5 1,30 JAN ? *', '0 5 1/28 JAN ? *',
        '0 5 1/28 * ? *', '0 5 L-3 * ? *',
        '0 5 1,1 * ? *', '0 5,5 1 * ? *',
        '0 5-5 1 * ? *', '0 5,6 1 * ? *',
        '0 5 ? * MON#1 *', '0 5 ? JAN,MAR MON#1 *',
        '0 5 ? FEB SAT#5 *', '0 5 ? * SUN#5 *',
        '0 5 15W * ? *', '0 5 31W * ? *',
        '0 5 L * ? *', '0 5 LW * ? *',
        '0 5 31 FEB ? *', '0 5 29 FEB ? 2027',
        '0 5 29 FEB ? 2028', '0 5 1 JAN ? 1970',
        '0 5 1 JAN ? 2025', '0 5 1 JAN ? 2030',
    ]:
        schedule='cron('+expression+')'
        yield 'calendar-'+expression, rule(schedule_expression=assign(schedule))
        yield 'archive-'+expression, rule(schedule_expression=assign(schedule),lifecycle={
            'move_to_cold_storage_after_days':assign('30'),
            'delete_after_days':assign('120'),
            'opt_in_to_archive_for_supported_resources':assign('true')})
    for schedule in [None,'cron(0 5 ? * * *)','cron(0 5 1 * ? *)']:
        settings={'copy_actions':{'arn:aws:backup:us-east-1:$account:backup-vault:Vault':{
            'target_backup_vault_arn':assign('arn:aws:backup:us-east-1:$account:backup-vault:Vault'),
            'lifecycle':{'move_to_cold_storage_after_days':assign('30'),'delete_after_days':assign('120'),'opt_in_to_archive_for_supported_resources':assign('true')}}}}
        if schedule: settings['schedule_expression']=assign(schedule)
        yield 'copy-archive-'+str(schedule),rule(**settings)


def detail_cases():
    for expression in [
        '0 5 ? JAN * 1970', '0 5 ? JAN * 2025',
        '0 5 ? JAN * 2030', '0 5 1 JAN,FEB ? 2030',
        '0 5 1,29 JAN,FEB ? *', '0 5 1,29 JAN,MAR ? *',
        '0 5 1,28 JAN,FEB ? *', '0 5 1,30 JAN,FEB ? *',
        '0 5 29 FEB ? 2028,2032', '0 5 29 FEB ? *',
        '0 5 1 JAN ? 2030,2031', '0 5 1 JAN ? 1970,1971',
    ]:
        schedule='cron('+expression+')'
        yield 'detail-calendar-'+expression, rule(schedule_expression=assign(schedule))
        yield 'detail-archive-'+expression, rule(schedule_expression=assign(schedule),lifecycle={
            'move_to_cold_storage_after_days':assign('30'),
            'delete_after_days':assign('120'),
            'opt_in_to_archive_for_supported_resources':assign('true')})


if __name__=='__main__':
    parser = probe_parser()
    parser.add_argument('--details', action='store_true')
    args = parser.parse_args()
    filename = 'organizations_backup_calendar_details.json' if args.details else 'organizations_backup_calendar.json'
    capture(detail_cases() if args.details else cases(), args.output or Path('.stackd/probes/iam') / filename, 'BACKUP_POLICY', args.account)
