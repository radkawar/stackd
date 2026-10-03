#!/usr/bin/env python3
"""Capture unattached backup policy schedule and archive admission."""
from organizations_backup_policy_probe import rule, assign
from organizations_policy_admission_probe import capture, probe_parser


def cases():
    for value in [
        'cron(0 5 ? * MON-FRI *)', 'cron(0/15 * ? * * *)',
        'cron(0 5 L * ? *)', 'cron(0 5 L-3 * ? *)',
        'cron(0 5 LW * ? *)', 'cron(0 5 15W * ? *)',
        'cron(0 5 ? * 6L *)', 'cron(0 5 ? * L *)',
        'cron(0 5 ? * MON#2 *)', 'cron(0 5 ? * MON#2,TUE#3 *)',
        'cron(0 5 ? NOV-FEB * *)', 'cron(0 20-2 ? * * *)',
        'cron(0 5 ? * mon *)', 'cron(0 5 ? JAN * 2200)',
        'cron(0 5 ? JAN * 1969)', 'cron(0 5 ? JAN * 2030-2035)',
        'cron(0 5 ? JAN * 2030/2)', 'cron(0 5 ? * * 9999)',
        'cron(0 5 ? * 0 *)', 'cron(0 5 1,15 * ? *)',
        'cron(0 5 ? * * *) ', 'cron(0  5 ? * * *)',
    ]:
        yield value, rule(schedule_expression=assign(value))
    for cold, expires in [(None,120),(30,60),(30,119),(30,120),(1,91),(30,121)]:
        lifecycle={'opt_in_to_archive_for_supported_resources':assign('true'), 'delete_after_days':assign(str(expires))}
        if cold is not None: lifecycle['move_to_cold_storage_after_days']=assign(str(cold))
        yield 'archive-'+str(cold)+'-'+str(expires), rule(lifecycle=lifecycle)


if __name__ == '__main__':
    args = probe_parser('organizations_backup_schedule.json').parse_args()
    capture(cases(), args.output, 'BACKUP_POLICY', args.account)
