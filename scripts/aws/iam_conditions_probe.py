#!/usr/bin/env python3
"""Capture actual IAM tag authorization with owned role sessions and a user."""
import argparse
import datetime
import json
import os
from pathlib import Path
import time
import uuid

from aws_cli import run as run_cli, error_code


def call(service, operation, parameters, credentials=None):
    env = os.environ.copy()
    if credentials:
        for key in list(env):
            if key.startswith('AWS_'):
                env.pop(key)
        env.update(AWS_ACCESS_KEY_ID=credentials['AccessKeyId'],
                   AWS_SECRET_ACCESS_KEY=credentials['SecretAccessKey'],
                   AWS_SESSION_TOKEN=credentials['SessionToken'],
                   AWS_EC2_METADATA_DISABLED='true')
    env['AWS_MAX_ATTEMPTS'] = '1'
    result = run_cli(service, operation, parameters, env, timeout=40,
                     options=['--region', 'us-east-1', '--no-paginate'])
    if result.returncode:
        code = error_code(result)
        if code == 'CLIError':
            raise RuntimeError(operation + ': ' + result.stderr.strip())
        return code, {}
    return 'Success', json.loads(result.stdout) if result.stdout.strip() else {}


def require(service, operation, parameters):
    code, output = call(service, operation, parameters)
    if code != 'Success':
        raise RuntimeError(operation + ': ' + code)
    return output


def capture_conditions(cases, output_path, simulation_cases=(), stored_policies=(), *, account):
    from aws_cli import require_account
    identity = require_account(account)
    suffix = uuid.uuid4().hex[:12]
    user_name = 'stackd-conditions-user-' + suffix
    role_name = 'stackd-conditions-role-' + suffix
    created_user = created_role = attached = user_policy = False
    capture = {'source': 'AWS IAM TagUser authorized through STS role session policies',
               'retrieved_at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
               'region': 'us-east-1',
               'scope': 'Owned keyless IAM target user and actor role; temporary credentials remain in memory.',
               'documentation': ['https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_condition-single-vs-multi-valued-context-keys.html',
                                 'https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_condition_operators.html'],
               'observations': [], 'cleanup': False}
    try:
        user = require('iam', 'create-user', {'UserName': user_name})['User']
        created_user = True
        trust = {'Version': '2012-10-17', 'Statement': [{'Effect': 'Allow', 'Action': 'sts:AssumeRole', 'Principal': {'AWS': 'arn:aws:iam::'+identity['Account']+':root'}}]}
        role = require('iam', 'create-role', {'RoleName': role_name, 'AssumeRolePolicyDocument': json.dumps(trust)})['Role']
        created_role = True
        base = {'Effect': 'Allow', 'Action': 'iam:TagUser', 'Resource': user['Arn']}
        require('iam', 'put-role-policy', {'RoleName': role_name, 'PolicyName': 'tag-target', 'PolicyDocument': json.dumps({'Version': '2012-10-17', 'Statement': [base]})})
        attached = True

        sessions = {}

        def attempt(condition, tags, deny=False, base_allow=False):
            statement = dict(base, Condition=condition)
            if deny:
                statement['Effect'] = 'Deny'
            policy = {'Version': '2012-10-17', 'Statement': [base, statement] if deny or base_allow else [statement]}
            document = json.dumps(policy)
            if document not in sessions:
                code, session = call('sts', 'assume-role', {'RoleArn': role['Arn'], 'RoleSessionName': 'conditions', 'DurationSeconds': 900, 'Policy': document})
                if code != 'Success':
                    return 'AssumeRole:'+code
                sessions[document] = session['Credentials']
            code, _ = call('iam', 'tag-user', {'UserName': user_name, 'Tags': tags}, sessions[document])
            return code

        deadline = time.monotonic()+60
        control = {'ForAnyValue:StringEquals': {'aws:TagKeys': 'team'}}
        while attempt(control, [{'Key':'team','Value':'capture'}]) != 'Success':
            if time.monotonic() >= deadline:
                raise RuntimeError('owned role permissions did not propagate within the probe window')
            time.sleep(1)

        for case in cases:
            code = attempt(case['condition'], case['tags'], case['deny'], case.get('base_allow',False))
            row = dict(case, code=code)
            capture['observations'].append(row)
            print(json.dumps(row,separators=(',',':')), flush=True)
        capture['simulation'] = []
        for request in simulation_cases:
            code, result = call('iam','simulate-custom-policy',request)
            capture['simulation'].append({'input':request,'code':code,'output':result})
        capture['policy_storage'] = []
        for document in stored_policies:
            code, _ = call('iam','put-user-policy', {'UserName':user_name,'PolicyName':'syntax','PolicyDocument':json.dumps(document)})
            user_policy = user_policy or code == 'Success'
            capture['policy_storage'].append({'document':document,'code':code})
    finally:
        if attached:
            require('iam', 'delete-role-policy', {'RoleName':role_name,'PolicyName':'tag-target'})
        if created_role:
            require('iam', 'delete-role', {'RoleName':role_name})
        if user_policy:
            require('iam','delete-user-policy',{'UserName':user_name,'PolicyName':'syntax'})
        if created_user:
            require('iam', 'delete-user', {'UserName':user_name})
        capture['cleanup'] = True
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(json.dumps(capture,indent=2)+'\n')
    print('Owned user, role and policy deleted')


def set_cases():
    for operator in ['StringEquals', 'StringNotEquals', 'StringEqualsIfExists', 'StringNotEqualsIfExists',
                     'ForAnyValue:StringEquals', 'ForAllValues:StringEquals',
                     'ForAnyValue:StringNotEquals', 'ForAllValues:StringNotEquals']:
        for keys in [[], ['team'], ['env'], ['team','env']]:
            tags = [{'Key':key, 'Value':'capture'} for key in keys]
            condition = {operator: {'aws:TagKeys':'team'}}
            for deny in [False, True]:
                yield {'condition':condition, 'tags':tags, 'deny':deny}
    for operator, value in [('Null','true'),('Null','false'),('StringEquals',''),('ForAllValues:StringEquals','capture'),('ForAnyValue:StringEquals','')]:
        for tags in [[{'Key':'team','Value':''}], [{'Key':'team','Value':'capture'}], [{'Key':'env','Value':'capture'}]]:
            condition = {operator: {'aws:RequestTag/team':value}}
            yield {'condition':condition, 'tags':tags, 'deny':False}
    for operator in ['StringEquals', 'StringNotEquals']:
        for value in ['${aws:TagKeys}', "${aws:TagKeys, 'fallback'}"]:
            for tags in [[{'Key':'team','Value':'fallback'}], [{'Key':'team','Value':'team'}], [{'Key':'team','Value':'team'}, {'Key':'env','Value':'env'}]]:
                condition = {operator: {'aws:RequestTag/team':value}}
                yield {'condition':condition, 'tags':tags, 'deny':False}


def value_cases():
    for operators, expected, values in [
        (['NumericEquals', 'NumericNotEquals'], '1', ['1', '2', 'no-number', '', '01', '+1', '1.0', '1e0', 'NaN', 'Infinity']),
        (['DateEquals', 'DateNotEquals'], '2030-01-01T00:00:00Z', ['2030-01-01T00:00:00Z', '2030-01-02T00:00:00Z', 'not-a-date', '', '1893456000', '2030-01-01']),
        (['Bool'], 'true', ['true', 'false', 'True', 'TRUE', 'yes', '1', '', ' true ']),
        (['Bool'], 'false', ['true', 'false', 'True', 'TRUE', 'yes', '1', '', ' true ']),
        (['BinaryEquals'], 'YQ==', ['YQ==', 'Yg==', 'YQ', 'YR==', 'no-binary', '', ' YQ== ']),
        (['IpAddress', 'NotIpAddress'], '192.0.2.0/24', ['192.0.2.1', '192.0.3.1', 'not-an-ip', '', '192.0.2.1/32', '192.000.2.1']),
        (['ArnLike', 'ArnNotLike'], 'arn:aws:iam::*:user/*', ['arn:aws:iam::123456789012:user/test', 'arn:aws:iam::123456789012:role/test', 'not-an-arn', '']),
    ]:
        for operator in operators:
            for value in values:
                for deny in [False, True]:
                    yield {'condition': {operator: {'aws:RequestTag/value': expected}},
                           'tags': [{'Key':'value', 'Value':value}], 'deny':deny}

    for operator in ['ForAnyValue:NumericEquals', 'ForAllValues:NumericEquals',
                     'ForAnyValue:NumericNotEquals', 'ForAllValues:NumericNotEquals']:
        for keys in [['no-number'], ['no-number','1'], ['no-number','2'], ['1','2']]:
            for deny in [False, True]:
                yield {'condition': {operator: {'aws:TagKeys':'1'}},
                       'tags':[{'Key':key,'Value':'capture'} for key in keys], 'deny':deny}

    yield from value_syntax_cases()
    yield from arn_array_cases()


def value_syntax_cases():
    for operator, expected, raw in [
        ('NumericEquals', '01', '1'), ('NumericEquals', '+1', '1'),
        ('NumericEquals', '1.', '1'), ('NumericEquals', 'NaN', '1'),
        ('NumericEquals', '9007199254740993', '9007199254740992'),
        ('NumericLessThan', '9007199254740993', '9007199254740992'),
        ('Bool', 'TRUE', 'true'), ('Bool', 'False', 'false'), ('Bool', 'yes', 'false'),
        ('DateEquals', '2030-01-01T00:00:00Z', '2030-01-01T00:00:00.0001Z'),
        ('DateEquals', '2030-01-01T00:00:00Z', '2030-01-01T00:00:00'),
        ('DateEquals', '2030-01-01T00:00:00Z', '+1893456000'),
        ('DateEquals', '2030-01-01T00:00:00.1231Z', '2030-01-01T00:00:00.1239Z'),
    ]:
        yield {'condition': {operator: {'aws:RequestTag/value':expected}},
               'tags':[{'Key':'value','Value':raw}], 'deny':False}
    for operator in ['ArnLike', 'ArnNotLike']:
        for resource in ['arn:aws:iam::123456789012:user/test', 'not-an-arn']:
            for deny in [False,True]:
                yield {'condition': {operator: {'aws:RequestTag/resource':'${aws:RequestTag/pattern}'}},
                       'tags':[{'Key':'pattern','Value':'not-an-arn'}, {'Key':'resource','Value':resource}], 'deny':deny}

    for operator, expected, values in [
        ('NumericEquals','NaN',['1','no-number']),
        ('NumericNotEquals','NaN',['1','no-number']),
        ('DateEquals','not-a-date',['2030-01-01T00:00:00Z','not-a-date']),
        ('DateNotEquals','not-a-date',['2030-01-01T00:00:00Z','not-a-date']),
        ('ArnLike','not-an-arn',['arn:aws:iam::123456789012:user/test','not-an-arn']),
        ('ArnNotLike','not-an-arn',['arn:aws:iam::123456789012:user/test','not-an-arn']),
        ('IpAddress','not-an-ip',['192.0.2.1','not-an-ip']),
        ('NotIpAddress','not-an-ip',['192.0.2.1','not-an-ip']),
        ('BinaryEquals','no-binary',['YQ==','no-binary']),
        ('Null','yes',['present']), ('Null','TRUE',['present']),
    ]:
        for raw in values:
            for deny, base_allow in [(False,False),(False,True),(True,True)]:
                yield {'condition':{operator:{'aws:RequestTag/value':expected}},
                       'tags':[{'Key':'value','Value':raw}], 'deny':deny, 'base_allow':base_allow}
    for operator in ['ArnLike','ArnNotLike']:
        for resource in ['arn:aws:iam::123456789012:user/test','not-an-arn']:
            yield {'condition':{operator:{'aws:RequestTag/resource':'${aws:RequestTag/pattern}'}},
                   'tags':[{'Key':'pattern','Value':'not-an-arn'},{'Key':'resource','Value':resource}],
                   'deny':False,'base_allow':True}


def arn_array_cases():
    for operator in ['ArnLike','ArnNotLike']:
        for valid in ['arn:aws:iam::*:user/*','arn:aws:iam::*:role/*']:
            for patterns in [['not-an-arn',valid],[valid,'not-an-arn']]:
                for deny in [False,True]:
                    yield {'condition':{operator:{'aws:RequestTag/value':patterns}},
                           'tags':[{'Key':'value','Value':'arn:aws:iam::123456789012:user/test'}], 'deny':deny}


def simulation_inputs():
    for op,expected,value in [('ArnLike','arn:aws:iam::*:user/*','not-an-arn'),
                              ('ArnNotLike','arn:aws:iam::*:user/*','not-an-arn'),
                              ('NumericNotEquals','1','no-number'),
                              ('DateNotEquals','2030-01-01T00:00:00Z','not-a-date'),
                              ('Bool','false','yes'),('NotIpAddress','192.0.2.0/24','not-an-ip')]:
        document = {'Version':'2012-10-17','Statement':{'Effect':'Allow','Action':'s3:GetObject','Resource':'*','Condition':{op:{'aws:RequestTag/value':expected}}}}
        yield {'PolicyInputList':[json.dumps(document)],'ActionNames':['s3:GetObject'],
               'ContextEntries':[{'ContextKeyName':'aws:RequestTag/value','ContextKeyValues':[value],'ContextKeyType':'string'}]}


def policy_documents():
    for op,value in [('NumericEquals','01'),('NumericEquals','NaN'),('NumericEquals','no-number'),
                     ('Bool','TRUE'),('Bool','yes'),('DateEquals','not-a-date'),
                     ('ArnLike','not-an-arn'),('IpAddress','not-an-ip'),('BinaryEquals','no-binary'),
                     ('Null','yes'),('Null','TRUE')]:
        yield {'Version':'2012-10-17','Statement':{'Effect':'Allow','Action':'iam:TagUser','Resource':'*','Condition':{op:{'aws:RequestTag/value':value}}}}


def ip_pairs():
    return [
        ('192.0.2.0/24', '192.0.2.0'), ('192.0.2.0/24', '192.0.2.255'),
        ('192.0.2.0/24', '192.0.3.1'), ('192.0.2.5/24', '192.0.2.1'),
        ('192.0.2.0/31', '192.0.2.1'), ('192.0.2.0/31', '192.0.2.2'),
        ('192.0.2.1', '192.0.2.1'), ('192.0.2.1', '192.0.2.2'),
        ('192.0.2.0/0', '203.0.113.1'), ('192.0.2.0/0', '2001:db8::1'),
        ('192.000.002.0/24', '192.0.2.1'), ('192.000.002.1', '192.0.2.1'),
        ('192.0.2.0/024', '192.0.2.1'), ('192.0.2.0/+24', '192.0.2.1'),
        ('192.0.2.0/24', '192.000.002.1'), ('192.0.2.0/24', '192.0.513'),
        ('192.0.2.0/24', '3221225985'), ('192.0.2.0/24', '192.0.2.1/32'),
        ('192.0.2.0/24', '::ffff:192.0.2.1'), ('192.0.2.0/24', '::FFFF:c000:201'),
        ('::ffff:192.0.2.0/120', '192.0.2.1'), ('::ffff:192.0.2.0/120', '::ffff:192.0.2.1'),
        ('::ffff:c000:200/120', '::ffff:c000:201'), ('::ffff:192.0.2.1', '::ffff:192.0.2.1'),
        ('::ffff:192.0.2.0/24', '192.0.2.1'), ('::192.0.2.0/120', '::192.0.2.1'),
        ('::/0', '::ffff:192.0.2.1'), ('::/0', '192.0.2.1'),
        ('::/0', '2001:db8::1'), ('2001:db8::1', '2001:db8::1'),
        ('2001:db8::1', '2001:db8::2'), ('2001:db8::1/128', '2001:db8::2'),
        ('2001:db8::/64', '2001:db8:0:0:ffff:ffff:ffff:ffff'),
        ('2001:db8::/64', '2001:db8:0:1::'), ('2001:db8::5/64', '2001:db8::1'),
        ('2001:DB8::/064', '2001:0db8:0000:0000:0000:0000:0000:0001'),
        ('2001:db8::/64', '2001:db8::192.0.2.1'),
        ('2001:db8::192.0.2.0/120', '2001:db8::c000:201'),
        ('192.0.2.0/33', '192.0.2.1'), ('2001:db8::/129', '2001:db8::1'),
        ('192.0.2.0/24', 'not-an-ip'), ('2001:db8::/64', '2001:db8:::1'),
        ('2001:db8::5/64', '2001:db8::5'), ('2001:db8::5/64', '2001:db8::6'),
        ('2001:db8::5/127', '2001:db8::4'), ('2001:db8::5/127', '2001:db8::5'),
        ('2001:db8::4/127', '2001:db8::4'), ('2001:db8::4/127', '2001:db8::5'),
        ('2001:db8::4/127', '2001:db8::6'), ('2001:db8::1/0', '2001:db8::1'),
    ]


def ip_cases():
    for network, address in ip_pairs() + ip_extra_pairs():
        for op in ['IpAddress', 'NotIpAddress']:
            for deny in [False, True]:
                yield {'condition':{op:{'aws:RequestTag/value':network}},
                       'tags':[{'Key':'value','Value':address}], 'deny':deny}


def ip_simulation_inputs():
    pairs = ip_pairs() + ip_extra_pairs() + [('::/0', 'fe80::1%eth0'), ('::/0', 'fe80::1%1'),
                         ('::/0', '[2001:db8::1]'), ('192.0.2.0/24', ' 192.0.2.1 ')]
    for network, address in pairs:
        for kind in ['string', 'ip']:
            statements = [{'Effect':'Allow','Action':action,'Resource':'*',
                           'Condition':{op:{'aws:SourceIp':network}}}
                          for action,op in [('s3:GetObject','IpAddress'), ('s3:PutObject','NotIpAddress')]]
            yield {'PolicyInputList':[json.dumps({'Version':'2012-10-17','Statement':statements})],
                   'ActionNames':['s3:GetObject','s3:PutObject'],
                   'ContextEntries':[{'ContextKeyName':'aws:SourceIp','ContextKeyValues':[address],'ContextKeyType':kind}]}
    yield from ip_spelling_inputs()
    yield from ip_resource_simulation_inputs()


def ip_spelling_inputs():
    for address, operator, candidates in [('192.000.002.1', 'StringEquals', ['192.000.002.1', '192.0.2.1']),
                                          ('::ffff:192.0.2.1', 'StringEquals', ['::ffff:192.0.2.1', '192.0.2.1']),
                                          ('::FFFF:c000:201', 'StringEquals', ['::FFFF:c000:201', '::ffff:c000:201', '192.0.2.1']),
                                          (':2001:db8::1', 'IpAddress', ['0:2001:db8::1/128','2001:db8::1/128','2001:db8::1:0/128']),
                                          ('2001:db8:0:0:0:0:0:1:', 'IpAddress', ['0:2001:db8::1/128','2001:db8::1/128','2001:db8::1:0/128'])]:
        actions = ['s3:GetObject','s3:PutObject','s3:DeleteObject'][:len(candidates)]
        statements = [{'Effect':'Allow','Action':action,'Resource':'*',
                       'Condition':{operator:{'aws:SourceIp':candidate}}}
                      for action,candidate in zip(actions,candidates)]
        yield {'PolicyInputList':[json.dumps({'Version':'2012-10-17','Statement':statements})],
               'ActionNames':actions,
               'ContextEntries':[{'ContextKeyName':'aws:SourceIp','ContextKeyValues':[address],'ContextKeyType':'ip'}]}


def ip_policy_documents():
    networks = list(dict.fromkeys(network for network, _ in ip_pairs()))
    for network in networks + ['2001:db8:::1/128','2001:db8::1:/128']:
        yield {'Version':'2012-10-17','Statement':{'Effect':'Allow','Action':'iam:TagUser','Resource':'*',
               'Condition':{'IpAddress':{'aws:RequestTag/value':network}}}}


def ip_resource_simulation_inputs():
    caller = 'arn:aws:iam::000000000000:user/stackd-ip-hypothetical'
    resource = 'arn:aws:s3:::stackd-ip-hypothetical/object'
    for network in ['192.0.2.0/24','not-an-ip','2001:db8::5/64']:
        statements = [{'Effect':'Allow','Action':action,'Resource':resource,'Principal':{'AWS':caller},
                       'Condition':{op:{'aws:SourceIp':network}}}
                      for action,op in [('s3:GetObject','IpAddress'),('s3:PutObject','NotIpAddress')]]
        yield {'ActionNames':['s3:GetObject','s3:PutObject'],
               'PolicyInputList':[json.dumps({'Statement':{'Effect':'Allow','Action':'iam:ListUsers','Resource':'*'}})],
               'ResourceArns':[resource], 'CallerArn':caller, 'ResourceOwner':caller,
               'ResourcePolicy':json.dumps({'Version':'2012-10-17','Statement':statements}),
               'ContextEntries':[{'ContextKeyName':'aws:SourceIp','ContextKeyValues':['192.0.2.1'],'ContextKeyType':'ip'}]}


def ip_extra_pairs():
    pairs = [(patterns,address) for patterns in [['not-an-ip','192.0.2.0/24'], ['192.0.2.0/24','not-an-ip']]
             for address in ['192.0.2.1','192.0.3.1']]
    pairs += [(patterns,'2001:db8::1') for patterns in [['2001:db8::5/64','2001:db8::/64'], ['2001:db8::/64','2001:db8::5/64']]]
    pairs += [('2001:db8::1/128',address) for address in ['2001:db8:::1','2001:db8::1:',':2001:db8::1','2001:db8::::1']]
    pairs += [('::/0',address) for address in [':::','2001::db8::1','2001::db8:::1','::ffff:::192.0.2.1']]
    return pairs


if __name__ == '__main__':
    from aws_cli import require_account
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('suite', choices=['sets', 'values', 'ip'])
    parser.add_argument("--account", required=True)
    args = parser.parse_args()
    require_account(args.account)
    suites = {'sets': (set_cases, lambda: (), lambda: ()),
              'values': (value_cases, simulation_inputs, policy_documents),
              'ip': (ip_cases, ip_simulation_inputs, ip_policy_documents)}
    cases, simulations, policies = suites[args.suite]
    capture_conditions(cases(), Path('.stackd/probes/iam/condition_'+args.suite+'.json'), simulations(), policies(), account=args.account)
