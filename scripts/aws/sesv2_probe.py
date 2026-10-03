#!/usr/bin/env python3
"""Read-only SES account and validation-only sends to AWS simulator recipients."""
import argparse
import datetime
import json
import os
from pathlib import Path
from aws_cli import observe, call

parser=argparse.ArgumentParser()
parser.add_argument('--output',required=True)
parser.add_argument('--account', required=True)
args=parser.parse_args()
env=dict(os.environ,AWS_DEFAULT_REGION='us-east-1',AWS_REGION='us-east-1',AWS_PAGER='')
identity=call('sts','get-caller-identity',env=env)
if identity['Account'] != args.account:
    raise SystemExit('unexpected native account')
# example.invalid can never have a verified native identity. All destinations are
# SES simulator recipients; there are no create/update/delete identity calls.
base={'FromEmailAddress':'stackd-probe@example.invalid','Destination':{'ToAddresses':['success@simulator.amazonses.com']},'Content':{'Simple':{'Subject':{'Data':'stackd validation probe'},'Body':{'Text':{'Data':'Not delivered: unverified reserved invalid sender.'}}}}}
cases=[('account','get-account',{}),('unverified-sender','send-email',base),('malformed-address','send-email',dict(base,Destination={'ToAddresses':['not-an-address']})),('empty-body','send-email',dict(base,Content={'Simple':{'Subject':{'Data':'validation'},'Body':{}}})),('missing-template','send-email',dict(base,Content={'Template':{'TemplateName':'stackd-never-created-validation-template','TemplateData':'{}'}}))]
result={'captured_at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'region':'us-east-1','account':identity['Account'],'safety':'No identities or account settings changed; only reserved invalid sender and AWS simulator recipients. No cleanup required.','calls':[]}
path=Path(args.output);path.parent.mkdir(parents=True,exist_ok=True)
for label,operation,parameters in cases:
    observed=observe('sesv2',operation,parameters,env,paginate=False)
    result['calls'].append({'label':label,'operation':operation,'parameters':parameters,**observed})
    path.write_text(json.dumps(result,indent=2)+'\n')
    print(label,observed['code'])
