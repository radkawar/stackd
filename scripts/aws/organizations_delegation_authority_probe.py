#!/usr/bin/env python3
"""Capture Organizations delegation authority and observed transition timing.

Temporarily enables Account Management trusted access and registers one existing
CREATED member. Restores both settings and removes owned roles, an unattached SCP
and the temporary resource policy. Never changes account data or attachments.
"""
import datetime
import json
import time
import uuid

from iam_conditions_probe import call as iam_call
from organizations_inputs_probe import call, required, probe_parser, verified_account, capture_path
from organizations_resource_policy_probe import cli, org_call


def main():
    args = probe_parser('organizations_delegation_authority.json').parse_args()
    management = verified_account(args.account)
    org = required('DescribeOrganization', {})['Organization']
    if org['MasterAccountId'] != management or org['FeatureSet'] != 'ALL': raise RuntimeError('ALL-features management account required')
    if call('DescribeResourcePolicy', {})['code'] != 'ResourcePolicyNotFoundException': raise RuntimeError('An existing delegation policy must not be replaced')
    principal = 'account.amazonaws.com'
    original_trust = any(s['ServicePrincipal'] == principal for s in required('ListAWSServiceAccessForOrganization', {})['EnabledServicePrincipals'])
    if required('ListDelegatedAdministrators', {})['DelegatedAdministrators']: raise RuntimeError('An existing delegated administrator must not be changed')
    member = next(a['Id'] for a in required('ListAccounts', {})['Accounts'] if a['Id'] != management and a['State'] == 'ACTIVE' and a['JoinedMethod'] == 'CREATED')
    member_admin = cli('sts', 'assume-role', {'RoleArn': 'arn:aws:iam::' + member + ':role/OrganizationAccountAccessRole', 'RoleSessionName': 'stackd-authority-setup', 'DurationSeconds': 900})['Credentials']
    prefix = 'stackd-org-authority-' + uuid.uuid4().hex[:10]
    role_arn = 'arn:aws:iam::' + member + ':role/' + prefix
    replacements = {management:'111111111111', member:'222222222222', org['Id']:'ORGANIZATION_ID', prefix:'OWNED_NAME'}
    capture = {'retrieved_at':datetime.datetime.now(datetime.timezone.utc).isoformat(), 'source':'Owned native Organizations delegation authority and transition samples',
        'scope':'Owned IAM roles and unattached SCP; temporary Account Management trust/delegation restored. No account-data or attachment changes. Account-list contents and management email omitted.',
        'observations':[], 'transitions':[], 'cleanup':{}}
    roles, target_id, trusted, registered, resource_policy = [], None, original_trust, False, False
    changed_at = time.monotonic()
    def normalized(value):
        text = json.dumps(value)
        for actual, label in sorted(replacements.items(), key=lambda item:-len(item[0])): text = text.replace(actual,label)
        return json.loads(text)
    def transition(action, parameters):
        nonlocal changed_at
        result = call(action, parameters)
        changed_at = time.monotonic()
        capture['transitions'].append(normalized({'action':action, 'input':parameters, 'code':result['code'], 'output':result['output']}))
        if result['code'] != 'Success': raise RuntimeError(action + ': ' + result['code'])
        print('transition ' + action + ': Success', flush=True)
        return result['output']
    def observe(case, action, parameters, actor, expected=None, count=3):
        deadline, consecutive, samples = time.monotonic()+60, 0, []
        while True:
            result = org_call(action, parameters, actor)
            samples.append({'seconds_after_change':round(time.monotonic()-changed_at,3), 'code':result['code'], 'status':result['status']})
            consecutive = consecutive+1 if expected is None or result['code']==expected else 0
            if consecutive >= count or time.monotonic() >= deadline: break
            time.sleep(1)
        output = result['output']
        if 'Accounts' in output: output = {'AccountCount':len(output['Accounts'])}
        if 'Organization' in output: output = {'OrganizationId':output['Organization']['Id']}
        capture['observations'].append(normalized({'case':case,'action':action,'input':parameters,'code':result['code'],'output':output,'samples':samples}))
        print(case + ': ' + result['code'], flush=True)
        if expected is not None and result['code'] != expected: raise RuntimeError(case + ': ' + result['code'])
        return result
    def assume(account, policy=None):
        args = {'RoleArn':'arn:aws:iam::'+account+':role/'+prefix, 'RoleSessionName':'stackd-authority', 'DurationSeconds':900}
        if policy is not None: args['Policy'] = json.dumps(policy)
        deadline = time.monotonic()+60
        while True:
            code, output = iam_call('sts','assume-role',args)
            if code == 'Success': return output['Credentials']
            if time.monotonic() >= deadline: raise RuntimeError('Owned role trust did not propagate: '+code)
            time.sleep(1)
    def put(statements):
        nonlocal resource_policy
        result = transition('PutResourcePolicy', {'Content':json.dumps({'Version':'2012-10-17','Statement':statements})})
        resource_policy = True
        replacements[result['ResourcePolicy']['ResourcePolicySummary']['Id']] = 'RESOURCE_POLICY_ID'
    try:
        trust = json.dumps({'Statement':[{'Effect':'Allow','Principal':{'AWS':'arn:aws:iam::'+management+':root'},'Action':'sts:AssumeRole'}]})
        for credentials in (member_admin,None):
            cli('iam','create-role',{'RoleName':prefix,'AssumeRolePolicyDocument':trust},credentials); roles.append((credentials,False))
            cli('iam','put-role-policy',{'RoleName':prefix,'PolicyName':prefix,'PolicyDocument':json.dumps({'Statement':[{'Effect':'Allow','Action':['organizations:DescribePolicy','organizations:ListAccounts','organizations:DescribeResourcePolicy','organizations:DescribeOrganization','organizations:UpdatePolicy','organizations:DeleteResourcePolicy'],'Resource':'*'}]})},credentials)
            roles[-1] = (credentials,True)
        actor = assume(member)
        target = required('CreatePolicy',{'Name':prefix,'Description':'Owned authority probe','Type':'SERVICE_CONTROL_POLICY','Content':'{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}'})['Policy']['PolicySummary']
        target_id, target_arn = target['Id'],target['Arn']; replacements[target_id] = 'POLICY_ID'
        query = {'PolicyId':target_id}
        observe('member-without-delegation','DescribePolicy',query,actor,'AccessDeniedException')
        observe('ordinary-member-describe-organization','DescribeOrganization',{},actor,'Success')
        # Session policies expose AWS's resource context without repeated IAM propagation.
        for caller, account in [('member',member),('management',management)]:
            for condition, operator, value in [('management-owner','StringEquals',management),('member-owner','StringEquals',member),('owner-absent','Null','true')]:
                limited = assume(account,{'Statement':[{'Effect':'Allow','Action':'organizations:DescribeOrganization','Resource':'*','Condition':{operator:{'aws:ResourceAccount':value}}}]})
                observe(caller+'-describe-org-'+condition,'DescribeOrganization',{},limited)
        if not trusted: transition('EnableAWSServiceAccess',{'ServicePrincipal':principal}); trusted=True
        transition('RegisterDelegatedAdministrator',{'AccountId':member,'ServicePrincipal':principal}); registered=True
        observe('trusted-without-resource-policy','DescribePolicy',query,actor,'Success')
        observe('trusted-list-without-resource-policy','ListAccounts',{},actor,'Success')
        observe('trusted-describe-absent-resource-policy','DescribeResourcePolicy',{},actor,'ResourcePolicyNotFoundException')
        for caller, account in [('trusted-member',member),('management',management)]:
            for condition, operator, value in [('management-owner','StringEquals',management),('member-owner','StringEquals',member),('owner-absent','Null','true')]:
                limited = assume(account,{'Statement':[{'Effect':'Allow','Action':'organizations:ListAccounts','Resource':'*','Condition':{operator:{'aws:ResourceAccount':value}}}]})
                observe(caller+'-list-'+condition,'ListAccounts',{},limited)
        observe('trusted-aws-managed-policy','DescribePolicy',{'PolicyId':'p-FullAWSAccess'},actor,'Success')
        for caller, account in [('trusted-member',member),('management',management)]:
            for condition, operator, value in [('management-owner','StringEquals',management),('member-owner','StringEquals',member),('aws-owner','StringEquals','aws'),('owner-absent','Null','true')]:
                limited = assume(account,{'Statement':[{'Effect':'Allow','Action':'organizations:DescribePolicy','Resource':'*','Condition':{operator:{'aws:ResourceAccount':value}}}]})
                observe(caller+'-aws-policy-'+condition,'DescribePolicy',{'PolicyId':'p-FullAWSAccess'},limited)
        statement = {'Effect':'Deny','Principal':{'AWS':member},'Action':['organizations:DescribePolicy','organizations:ListAccounts','organizations:DescribeResourcePolicy','organizations:DescribeOrganization'],'Resource':'*','Condition':{'ArnEquals':{'aws:PrincipalArn':role_arn}}}
        put([statement])
        observe('trusted-resource-policy-denies-read','DescribePolicy',query,actor,count=5)
        observe('trusted-resource-policy-denies-aws-policy','DescribePolicy',{'PolicyId':'p-FullAWSAccess'},actor)
        observe('trusted-resource-policy-denies-list','ListAccounts',{},actor)
        observe('trusted-resource-policy-denies-own-description','DescribeResourcePolicy',{},actor)
        observe('trusted-resource-policy-denies-organization-description','DescribeOrganization',{},actor)
        observe('trusted-without-write-delegation','UpdatePolicy',{'PolicyId':target_id,'Name':prefix+'-ungranted'},actor,'AccessDeniedException')
        write = {'Effect':'Allow','Principal':{'AWS':member},'Action':'organizations:UpdatePolicy','Resource':target_arn,'Condition':{'ArnEquals':{'aws:PrincipalArn':role_arn}}}
        put([statement,write])
        observe('trusted-with-write-delegation','UpdatePolicy',{'PolicyId':target_id,'Name':prefix+'-delegated'},actor,'Success',count=1)
        transition('DeregisterDelegatedAdministrator',{'AccountId':member,'ServicePrincipal':principal}); registered=False
        observe('deregistered-resource-policy-denies-read','DescribePolicy',query,actor,'AccessDeniedException')
        observe('ordinary-member-resource-policy-denies-description','DescribeOrganization',{},actor)
        observe('deregistered-resource-policy-allows-write','UpdatePolicy',{'PolicyId':target_id,'Name':prefix+'-policy-only'},actor,'Success',count=1)
        statement['Effect']='Allow'
        statement['Resource']=[target_arn,'*']
        for iteration in range(3):
            put([statement])
            observe('grant-'+str(iteration+1),'DescribePolicy',query,actor,'Success')
            revoked=dict(statement,Effect='Deny')
            put([revoked])
            observe('revoke-'+str(iteration+1),'DescribePolicy',query,actor,'AccessDeniedException')
        put([statement])
        observe('resource-delegate-describes-policy','DescribeResourcePolicy',{},actor,'Success')
        observe('resource-delegate-describes-aws-policy','DescribePolicy',{'PolicyId':'p-FullAWSAccess'},actor)
        for condition, operator, value in [('management-owner','StringEquals',management),('member-owner','StringEquals',member),('owner-absent','Null','true')]:
            put([statement])
            limited = assume(management,{'Statement':[{'Effect':'Allow','Action':'organizations:DeleteResourcePolicy','Resource':'*','Condition':{operator:{'aws:ResourceAccount':value}}}]})
            result = observe('management-delete-resource-policy-'+condition,'DeleteResourcePolicy',{},limited,count=1)
            if result['code']=='Success': resource_policy=False
        put([statement])
        transition('DeleteResourcePolicy',{}); resource_policy=False
        observe('resource-policy-deleted','DescribePolicy',query,actor,'AccessDeniedException')
    finally:
        if resource_policy: required('DeleteResourcePolicy',{})
        if registered: required('DeregisterDelegatedAdministrator',{'AccountId':member,'ServicePrincipal':principal})
        if trusted and not original_trust: required('DisableAWSServiceAccess',{'ServicePrincipal':principal})
        if target_id: required('DeletePolicy',{'PolicyId':target_id})
        for credentials, inline in reversed(roles):
            if inline: cli('iam','delete-role-policy',{'RoleName':prefix,'PolicyName':prefix},credentials)
            cli('iam','delete-role',{'RoleName':prefix},credentials)
        capture['cleanup']={'resource_policy_absent':call('DescribeResourcePolicy',{})['code']=='ResourcePolicyNotFoundException',
            'delegations_restored':not required('ListDelegatedAdministrators',{})['DelegatedAdministrators'],
            'trusted_access_restored':any(s['ServicePrincipal']==principal for s in required('ListAWSServiceAccessForOrganization',{})['EnabledServicePrincipals'])==original_trust}
        # Normalize resource-policy IDs discovered after the transition was recorded.
        capture=normalized(capture)
        capture_path(args.output).write_text(json.dumps(capture,indent=2)+'\n')
        print('Cleanup:',capture['cleanup'],flush=True)
        if not all(capture['cleanup'].values()): raise RuntimeError('Delegation settings did not restore')


if __name__=='__main__':
    main()
