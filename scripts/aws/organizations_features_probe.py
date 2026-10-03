#!/usr/bin/env python3
"""Capture all-features validation on the owned, already-ALL organization.

The precondition prevents starting a migration. No memberships or feature sets
are changed; member calls use the existing account access role.
"""
import datetime
import json

from organizations_inputs_probe import required, probe_parser, verified_account, capture_path
from organizations_resource_policy_probe import cli, org_call


def main():
    args = probe_parser('organizations_features.json').parse_args()
    owner = verified_account(args.account)
    organization = required('DescribeOrganization', {})['Organization']
    if organization['FeatureSet'] != 'ALL': raise RuntimeError('Probe requires an already-ALL organization')
    accounts = required('ListAccounts', {})['Accounts']
    member = next(a for a in accounts if a['Id'] != owner and a['State'] == 'ACTIVE' and a['JoinedMethod'] == 'CREATED')
    role = 'arn:aws:iam::'+member['Id']+':role/OrganizationAccountAccessRole'
    recipient = cli('sts','assume-role',{'RoleArn':role,'RoleSessionName':'stackd-features-read','DurationSeconds':900})['Credentials']
    capture = {'retrieved_at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'scope':'Already-ALL organization; no migration or membership changes','observations':[]}
    for name,params,credentials in [('already-all',{},None),('ignored-field',{'Unknown':'ignored'},None),('member',{},recipient)]:
        result = org_call('EnableAllFeatures',params,credentials)
        if result['code']=='Success':raise RuntimeError('Unexpected successful migration on an already-ALL organization')
        capture['observations'].append(dict(case=name,action='EnableAllFeatures',input=params,**result))
        print(name+': '+result['code'],flush=True)
    capture['unchanged'] = organization == required('DescribeOrganization',{})['Organization'] and sorted((a['Id'],a['State']) for a in accounts) == sorted((a['Id'],a['State']) for a in required('ListAccounts',{})['Accounts'])
    text=json.dumps(capture,indent=2)
    for actual,label in [(owner,'111111111111'),(member['Id'],'222222222222'),(organization['Id'],'o-exampleorgid')]:text=text.replace(actual,label)
    capture_path(args.output).write_text(text+'\n')

if __name__ == '__main__':main()
