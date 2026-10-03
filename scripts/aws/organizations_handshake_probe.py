#!/usr/bin/env python3
"""Capture handshake validation without changing account membership.

Targets are existing owned members. Account-ID invitations are rejected; email
invitations can open; acceptance of an existing member returns an error but
consumes the handshake. Open invitations are canceled or declined. No standalone accounts are
invited and existing handshakes are not modified.
"""
import datetime
import json

from organizations_inputs_probe import required, probe_parser, verified_account, capture_path
from organizations_resource_policy_probe import cli, org_call


def main():
    args = probe_parser('organizations_handshakes.json').parse_args()
    owner = verified_account(args.account)
    organization = required('DescribeOrganization', {})['Organization']
    accounts = required('ListAccounts', {})['Accounts']
    member = next(a for a in accounts if a['Id'] != owner and a['State'] == 'ACTIVE' and a['JoinedMethod'] == 'CREATED')
    target = {'Type': 'ACCOUNT', 'Id': member['Id']}
    replacements = {owner: '111111111111', member['Id']: '222222222222', member['Email']: 'member@example.test', organization['Id']: 'o-exampleorgid', organization['Id'][2:]: 'exampleorgid'}
    capture = {'retrieved_at': datetime.datetime.now(datetime.timezone.utc).isoformat(), 'source': 'Native Organizations handshake validation and received-list authorization',
               'scope': 'Owned existing-member invitation lifecycle; no membership changes. Lists project only handshakes created by this run. Session policies use the retained account access role.', 'observations': [], 'cleanup': False}
    owned = []
    for account in accounts:
        replacements.setdefault(account['Email'], 'management@example.test' if account['Id'] == owner else 'other@example.test')
        replacements[account['Name']] = 'Management' if account['Id'] == owner else 'Member'
    def observe(name, action, parameters, credentials=None):
        result = org_call(action, parameters, credentials)
        if action == 'InviteAccountToOrganization' and result['code'] == 'Success':
            handshake = result['output']['Handshake']
            owned.append(handshake['Id'])
            replacements[handshake['Id']] = 'h-' + str(len(owned)).zfill(8)
        if 'Handshakes' in result['output']:
            result['output']['Handshakes'] = [h for h in result['output']['Handshakes'] if h['Id'] in owned]
        row = dict(case=name, action=action, input=parameters, **result)
        text = json.dumps(row)
        for actual, label in sorted(replacements.items(), key=lambda item:-len(item[0])): text = text.replace(actual, label)
        capture['observations'].append(json.loads(text))
        print(name + ': ' + result['code'], flush=True)
        return result
    cases = [({}, 'missing-target'), ({'Target':{}}, 'empty-target'), ({'Target':dict(target,Type='ORGANIZATION')}, 'organization-target'),
             ({'Target':dict(target,Type='INVALID')}, 'invalid-target-type'), ({'Target':dict(target,Id='bad')}, 'bad-account-id'),
             ({'Target':{'Type':'EMAIL','Id':'invalid'}}, 'bad-email'), ({'Target':target}, 'existing-member'),
             ({'Target':target,'Notes':'x'*1025}, 'notes-too-long'),
             ({'Target':target,'Tags':[{'Key':'same','Value':'one'},{'Key':'same','Value':'two'}]}, 'duplicate-tags')]
    try:
        for parameters, name in cases: observe(name, 'InviteAccountToOrganization', parameters)
        for action in ['DescribeHandshake','AcceptHandshake','DeclineHandshake','CancelHandshake']:
            for value in [None, '', 'bad', 'h-00000000']:
                observe(action+'-'+str(value), action, {} if value is None else {'HandshakeId':value})
        for action in ['ListHandshakesForAccount','ListHandshakesForOrganization']:
            for label, parameters in [('empty',{}),('both-filters',{'Filter':{'ActionType':'INVITE','ParentHandshakeId':'h-00000000'}}),
                                      ('empty-filter',{'Filter':{}}),('unknown-parent',{'Filter':{'ParentHandshakeId':'h-00000000'}}),
                                      ('bad-action',{'Filter':{'ActionType':'invalid'}}),('bad-token',{'NextToken':'bad'})]:
                observe(action+'-'+label,action,parameters)
        role = 'arn:aws:iam::'+member['Id']+':role/OrganizationAccountAccessRole'
        for label, operator, value in [('management-owner','StringEquals',owner),('member-owner','StringEquals',member['Id']),('owner-absent','Null','true')]:
            policy = {'Statement':[{'Effect':'Allow','Action':'organizations:ListHandshakesForAccount','Resource':'*','Condition':{operator:{'aws:ResourceAccount':value}}}]}
            session = cli('sts','assume-role',{'RoleArn':role,'RoleSessionName':'stackd-handshake-read','DurationSeconds':900,'Policy':json.dumps(policy)})['Credentials']
            observe(label,'ListHandshakesForAccount',{},session)
        recipient = cli('sts','assume-role',{'RoleArn':role,'RoleSessionName':'stackd-handshake-recipient','DurationSeconds':900})['Credentials']
        email_input = {'Target':{'Type':'EMAIL','Id':member['Email']}, 'Notes':'Owned stackd handshake lifecycle capture', 'Tags':[{'Key':'owner','Value':'stackd'}]}
        first = observe('email-invitation','InviteAccountToOrganization',email_input)['output']['Handshake']['Id']
        selector = {'HandshakeId':first}
        observe('duplicate-email','InviteAccountToOrganization',email_input)
        observe('sender-description','DescribeHandshake',selector)
        observe('recipient-description','DescribeHandshake',selector,recipient)
        observe('recipient-list','ListHandshakesForAccount',{},recipient)
        observe('sender-list','ListHandshakesForOrganization',{})
        observe('sender-accept','AcceptHandshake',selector)
        observe('sender-decline','DeclineHandshake',selector)
        observe('recipient-cancel','CancelHandshake',selector,recipient)
        observe('recipient-already-member','AcceptHandshake',selector,recipient)
        observe('description-after-failed-accept','DescribeHandshake',selector)
        observe('cancel-accepted','CancelHandshake',selector)
        observe('cancel-accepted-again','CancelHandshake',selector)
        observe('decline-accepted','DeclineHandshake',selector,recipient)
        observe('accept-accepted','AcceptHandshake',selector,recipient)
        second = observe('email-after-accept-error','InviteAccountToOrganization',email_input)['output']['Handshake']['Id']
        selector = {'HandshakeId':second}
        observe('decline','DeclineHandshake',selector,recipient)
        observe('decline-again','DeclineHandshake',selector,recipient)
        observe('accept-declined','AcceptHandshake',selector,recipient)
        observe('cancel-declined','CancelHandshake',selector)
        third = observe('email-after-decline','InviteAccountToOrganization',email_input)['output']['Handshake']['Id']
        selector = {'HandshakeId':third}
        observe('cancel','CancelHandshake',selector)
        observe('cancel-again','CancelHandshake',selector)
        observe('accept-canceled','AcceptHandshake',selector,recipient)
        observe('decline-canceled','DeclineHandshake',selector,recipient)
    finally:
        for id in owned:
            handshake = required('DescribeHandshake',{'HandshakeId':id})['Handshake']
            if handshake['State'] in ('OPEN','REQUESTED'):
                required('CancelHandshake',{'HandshakeId':id})
        capture['membership_unchanged'] = sorted((a['Id'],a['State']) for a in required('ListAccounts',{})['Accounts']) == sorted((a['Id'],a['State']) for a in accounts)
        capture['cleanup'] = all(required('DescribeHandshake',{'HandshakeId':id})['Handshake']['State'] not in ('OPEN','REQUESTED') for id in owned)
        capture_path(args.output).write_text(json.dumps(capture,indent=2)+'\n')


if __name__ == '__main__': main()
