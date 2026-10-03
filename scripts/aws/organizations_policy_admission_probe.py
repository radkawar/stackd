#!/usr/bin/env python3
"""Capture policy admission using owned unattached policies."""
import datetime
import json
import uuid
import time

from organizations_inputs_probe import call, required, probe_parser, verified_account, capture_path


def capture(observations, output, kind, account):
    owner = verified_account(account)
    prefix='stackd-policy-admission-'+uuid.uuid4().hex[:8]
    capture={'retrieved_at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'scope':'Unattached '+kind+' admission; no attachments or service enablement','observations':[],'cleanup':False}
    path = capture_path(output)
    pending=[]
    def save():
        text=json.dumps(capture,indent=2).replace(owner,'111111111111').replace(prefix,'stackd-policy-admission-owned')
        path.write_text(text+'\n')
    try:
        for index,(label,content) in enumerate(observations):
            parameters={'Name':prefix+'-'+str(index),'Type':kind,'Description':'Owned unattached admission capture','Content':content if isinstance(content,str) else json.dumps(content)}
            for attempt in range(6):
                result=call('CreatePolicy',parameters)
                if result['code']!='TooManyRequestsException': break
                time.sleep(2**attempt)
            if result['code']=='TooManyRequestsException': raise RuntimeError('Admission capture remained throttled')
            if result['code']=='Success':
                policy=result['output']['Policy']['PolicySummary']['Id']
                pending.append(policy)
                result['output']['Policy']['PolicySummary']['Id']='POLICY_ID'
                result['output']['Policy']['PolicySummary']['Arn']='POLICY_ARN'
                required('DeletePolicy',{'PolicyId':policy})
                pending.remove(policy)
            capture['observations'].append(dict(case=label,action='CreatePolicy',input=parameters,**result))
            print(label+': '+result['code'],flush=True)
            save()
    finally:
        for policy in pending:
            result=call('DeletePolicy',{'PolicyId':policy})
            if result['code'] not in ['Success','PolicyNotFoundException']: raise RuntimeError('Could not remove owned policy '+policy)
        capture['cleanup']=True
        save()
        print('cleanup: True',flush=True)
