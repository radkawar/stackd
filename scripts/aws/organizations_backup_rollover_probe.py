#!/usr/bin/env python3
"""Observe time-dependent admission and metadata updates on one owned policy."""
import datetime
import json
import time
import uuid

from organizations_inputs_probe import call, probe_parser, verified_account, capture_path
from organizations_backup_policy_probe import rule, assign


def main():
    args = probe_parser('organizations_backup_rollover.json').parse_args()
    owner = verified_account(args.account)
    now=datetime.datetime.now(datetime.timezone.utc)
    if now.minute not in range(1,58): raise RuntimeError('Capture requires a minute between 1 and 57')
    prefix='stackd-calendar-rollover-'+uuid.uuid4().hex[:8]
    expression=f'cron({now.minute-1},{now.minute+1} {now.hour} ? * * *)'
    content=json.dumps(rule(schedule_expression=assign(expression)))
    deadline=now.replace(minute=now.minute+1,second=3,microsecond=0)
    fixture={'retrieved_at':now.isoformat(),'scope':'Unattached backup policy admission across one minute; no execution or service enablement','observations':[],'cleanup':False}
    path = capture_path(args.output)
    policy=None
    def save():
        text=json.dumps(fixture,indent=2).replace(owner,'111111111111').replace(prefix,'stackd-calendar-rollover-owned')
        if policy: text=text.replace(policy,'POLICY_ID')
        path.write_text(text+'\n')
    def observe(label,action,parameters):
        at=datetime.datetime.now(datetime.timezone.utc).isoformat()
        response=call(action,parameters)
        fixture['observations'].append(dict(case=label,action=action,at=at,input=parameters,**response))
        save()
        print(label+': '+response['code'],flush=True)
        return response
    try:
        created=observe('admitted-before-occurrence','CreatePolicy',{'Name':prefix,'Description':'Before schedule occurrence','Type':'BACKUP_POLICY','Content':content})
        if created['code']!='Success': raise RuntimeError('Owned schedule was not admitted')
        policy=created['output']['Policy']['PolicySummary']['Id']
        save()
        while datetime.datetime.now(datetime.timezone.utc)<deadline:
            time.sleep(min(15,(deadline-datetime.datetime.now(datetime.timezone.utc)).total_seconds()))
        observe('read-after-occurrence','DescribePolicy',{'PolicyId':policy})
        observe('metadata-after-occurrence','UpdatePolicy',{'PolicyId':policy,'Description':'After schedule occurrence'})
        observe('content-after-occurrence','UpdatePolicy',{'PolicyId':policy,'Content':content})
        observe('read-after-rejected-update','DescribePolicy',{'PolicyId':policy})
    finally:
        if policy:
            response=call('DeletePolicy',{'PolicyId':policy})
            if response['code'] not in ['Success','PolicyNotFoundException']: raise RuntimeError('Owned policy cleanup failed')
        fixture['cleanup']=True
        save()
        print('cleanup: True',flush=True)


if __name__=='__main__': main()
