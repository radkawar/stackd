#!/usr/bin/env python3
"""Capture effective-policy publication after owned non-enforcing tag changes."""
import datetime
import json
import time
import uuid

from organizations_inputs_probe import call, required, probe_parser, verified_account, capture_path


def main():
    args = probe_parser('organizations_policy_publication.json').parse_args()
    owner = verified_account(args.account)
    root = required('ListRoots', {})['Roots'][0]
    organization = required('DescribeOrganization', {})['Organization']
    if organization['FeatureSet'] != 'ALL' or any(p['Type'] == 'TAG_POLICY' for p in root['PolicyTypes']):
        raise RuntimeError('Requires ALL with TAG_POLICY disabled')
    accounts = required('ListAccounts', {})['Accounts']
    member = next(a['Id'] for a in accounts if a['Id'] != owner and a['State'] == 'ACTIVE')
    name = 'stackd-publication-' + uuid.uuid4().hex[:10]
    key = name.lower()
    path = capture_path(args.output)
    capture = {'retrieved_at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'scope':'One temporary non-enforcing tag policy; original memberships unchanged','transitions':[],'cleanup':False}
    replacements = {owner:'111111111111',member:'222222222222',root['Id']:'r-example',organization['Id']:'o-exampleorgid',name:'stackd-publication-owned'}
    def save():
        text = json.dumps(capture,indent=2)
        for actual,label in replacements.items(): text=text.replace(actual,label)
        path.write_text(text+'\n')
    def document(value): return json.dumps({'tags':{key:{'tag_value':{'@@assign':[value]}}}})
    def poll(label, mutations, desired):
        row={'case':label,'mutations':mutations,'observations':[]}
        capture['transitions'].append(row)
        start=time.monotonic()
        streak=0
        while time.monotonic()-start<45:
            result=call('DescribeEffectivePolicy',{'PolicyType':'TAG_POLICY','TargetId':member})
            policy=result['output'].get('EffectivePolicy',{})
            content=json.loads(policy.get('PolicyContent','{}'))
            row['observations'].append({'elapsed_seconds':round(time.monotonic()-start,3),'code':result['code'],'content':content,'last_updated':policy.get('LastUpdatedTimestamp')})
            value=content.get('tags',{}).get(key,{}).get('tag_value')
            ready=result['code']=='EffectivePolicyNotFoundException' if desired is None else result['code']=='Success' and (content=={} if desired=='' else value==[desired])
            streak=streak+1 if ready else 0
            save()
            if streak==3:
                print(label+': converged after '+str(len(row['observations']))+' samples',flush=True)
                return
            time.sleep(.25)
        raise RuntimeError(label+' did not converge; inspect capture')
    def mutation(action,params):
        required(action,params)
        return {'action':action,'input':params}
    policy=None
    attached=False
    enabled=False
    try:
        op=mutation('EnablePolicyType',{'RootId':root['Id'],'PolicyType':'TAG_POLICY'})
        enabled=True
        poll('enable',[op],'')
        policy=required('CreatePolicy',{'Name':name,'Description':'Owned publication capture','Type':'TAG_POLICY','Content':document('one')})['Policy']['PolicySummary']['Id']
        replacements[policy]='POLICY_ID'
        op=mutation('AttachPolicy',{'PolicyId':policy,'TargetId':member})
        attached=True
        poll('attach',[op],'one')
        op=mutation('UpdatePolicy',{'PolicyId':policy,'Content':document('two')})
        poll('update',[op],'two')
        ops=[mutation('UpdatePolicy',{'PolicyId':policy,'Content':document('three')}),mutation('UpdatePolicy',{'PolicyId':policy,'Content':document('four')})]
        poll('rapid-updates',ops,'four')
        op=mutation('DetachPolicy',{'PolicyId':policy,'TargetId':member})
        attached=False
        poll('detach',[op],'')
        op=mutation('AttachPolicy',{'PolicyId':policy,'TargetId':member})
        attached=True
        poll('reattach',[op],'four')
        op=mutation('DisablePolicyType',{'RootId':root['Id'],'PolicyType':'TAG_POLICY'})
        enabled=False
        attached=False
        poll('disable',[op],None)
        op=mutation('EnablePolicyType',{'RootId':root['Id'],'PolicyType':'TAG_POLICY'})
        enabled=True
        poll('reenable',[op],'')
        op=mutation('DisablePolicyType',{'RootId':root['Id'],'PolicyType':'TAG_POLICY'})
        enabled=False
        poll('disable-again',[op],None)
    finally:
        failures=[]
        if attached:
            result=call('DetachPolicy',{'PolicyId':policy,'TargetId':member})
            if result['code'] not in ['Success','PolicyNotAttachedException']: failures.append(result)
        if policy:
            result=call('DeletePolicy',{'PolicyId':policy})
            if result['code']!='Success': failures.append(result)
        if enabled:
            result=call('DisablePolicyType',{'RootId':root['Id'],'PolicyType':'TAG_POLICY'})
            if result['code']!='Success': failures.append(result)
        capture['cleanup']=not failures and required('ListRoots',{})['Roots'][0]==root
        capture['memberships_unchanged']=sorted((a['Id'],a['State']) for a in accounts)==sorted((a['Id'],a['State']) for a in required('ListAccounts',{})['Accounts'])
        capture['cleanup_failures']=failures
        save()
        print('cleanup: '+str(capture['cleanup']),flush=True)
        if not capture['cleanup'] or not capture['memberships_unchanged']: raise RuntimeError('Original organization state was not restored')

if __name__ == '__main__': main()
