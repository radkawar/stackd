#!/usr/bin/env python3
"""Capture RAM token replay and deleted-version identity on one owned permission.

No shares, Organizations configuration, account placements or standing permissions
are changed. A before-call hook removes SDK-injected tokens where the case requires
an actually omitted clientToken; ordinary signing still authenticates the request.
"""
import argparse
import datetime
import json
from pathlib import Path
import time
import uuid

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument("--account", required=True)
    args = parser.parse_args()
    if args.output.exists():
        raise ValueError('Refusing to overwrite existing native evidence')
    session = boto3.Session(region_name='us-east-1')
    account = session.client('sts').get_caller_identity()['Account']
    if account != args.account:
        raise ValueError('Native capture requires the approved account')
    client = session.client('ram', config=Config(retries={'max_attempts': 0}))
    prefix = 'stackd-ram-identity-' + uuid.uuid4().hex[:12]
    evidence = {'source':'Native AWS RAM, one exact-owned customer permission; unmodified signed SDK except explicitly omitted token',
                'observed_at':datetime.datetime.now(datetime.timezone.utc).isoformat(), 'region':'us-east-1', 'account':account,
                'documentation':['https://docs.aws.amazon.com/ram/latest/APIReference/API_CreatePermissionVersion.html',
                                 'https://docs.aws.amazon.com/ram/latest/APIReference/API_DeletePermissionVersion.html'],
                'calls':[], 'cleanup':[], 'complete':False}
    omit_token = False
    active_row = None
    arn = None
    def strip_injected_token(params, **_):
        if omit_token:
            body = json.loads(params['body'])
            body.pop('clientToken', None)
            params['body'] = json.dumps(body).encode()
        if active_row is not None and params.get('body'):
            active_row['raw_request_body'] = json.loads(params['body'])
    def capture_raw_response(http_response, **_):
        if active_row is not None:
            active_row['raw_response_body'] = json.loads(http_response.content)
    client.meta.events.register('before-call.ram', strip_injected_token)
    client.meta.events.register('after-call.ram', capture_raw_response)
    def save():
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(evidence, indent=2, default=str)+'\n')
    def call(label, operation, omitted=False, required=False, **parameters):
        nonlocal omit_token, active_row
        omit_token = omitted
        row = {'label':label, 'operation':operation, 'input':parameters, 'client_token_omitted_on_wire':omitted}
        active_row = row
        evidence['calls'].append(row)
        try:
            out = getattr(client, operation)(**parameters)
            row.update(code='Success', output=out)
            return out
        except ClientError as error:
            row.update(code=error.response['Error']['Code'], error=error.response['Error'])
            if required:
                raise
            return None
        finally:
            omit_token = False
            active_row = None
            save()
    template = lambda action: json.dumps({'Effect':'Allow','Action':[action] if isinstance(action, str) else action}, separators=(',', ':'))
    try:
        created = call('create-without-token', 'create_permission', omitted=True, required=True, name=prefix, resourceType='ssm:Parameter', policyTemplate=template('ssm:GetParameter'))
        arn = created['permission']['arn']
        evidence['permission_arn'] = arn
        evidence['create_response_has_client_token'] = 'clientToken' in created
        if 'clientToken' in created:
            call('replay-returned-create-token', 'create_permission', required=True, name=prefix, resourceType='ssm:Parameter', policyTemplate=template('ssm:GetParameter'), clientToken=created['clientToken'])
        call('duplicate-active-template', 'create_permission_version', permissionArn=arn, policyTemplate=template('ssm:GetParameter'), clientToken=prefix+'-duplicate-active')
        first = dict(permissionArn=arn, policyTemplate=template('ssm:GetParameters'), clientToken=prefix+'-version-a')
        original = call('create-version-a', 'create_permission_version', required=True, **first)
        version = original['permission']['version']
        call('default-original', 'set_default_permission_version', required=True, permissionArn=arn, permissionVersion=1)
        call('delete-version-a', 'delete_permission_version', required=True, permissionArn=arn, permissionVersion=int(version))
        call('get-deleted-version', 'get_permission', permissionArn=arn, permissionVersion=int(version))
        call('list-after-version-delete', 'list_permission_versions', required=True, permissionArn=arn)
        call('replay-a-after-delete', 'create_permission_version', **first)
        replacement = call('create-version-b', 'create_permission_version', required=True, permissionArn=arn, policyTemplate=template('ssm:GetParameterHistory'), clientToken=prefix+'-version-b')
        evidence['deleted_version'] = version
        evidence['replacement_version'] = replacement['permission']['version']
        call('read-replacement-version', 'get_permission', required=True, permissionArn=arn, permissionVersion=int(replacement['permission']['version']))
        call('replay-a-after-reuse', 'create_permission_version', **first)
        generated = call('create-version-without-token', 'create_permission_version', omitted=True, required=True, permissionArn=arn, policyTemplate=template('ssm:DescribeParameters'))
        evidence['version_response_has_client_token'] = 'clientToken' in generated
        if 'clientToken' in generated:
            call('replay-returned-version-token', 'create_permission_version', permissionArn=arn, policyTemplate=template('ssm:DescribeParameters'), clientToken=generated['clientToken'])
        for label, action in [('four', ['ssm:GetParameter', 'ssm:GetParameters']), ('five', ['ssm:GetParameterHistory', 'ssm:GetParameters'])]:
            call('fill-active-version-' + label, 'create_permission_version', required=True, permissionArn=arn, policyTemplate=template(action), clientToken=prefix+'-version-'+label)
        call('delete-interior-version', 'delete_permission_version', required=True, permissionArn=arn, permissionVersion=int(generated['permission']['version']))
        newest = call('create-after-interior-delete', 'create_permission_version', required=True, permissionArn=arn, policyTemplate=template(['ssm:DescribeParameters', 'ssm:GetParameter']), clientToken=prefix+'-version-after-hole')
        call('list-at-active-version-limit', 'list_permission_versions', required=True, permissionArn=arn)
        call('exceed-active-version-limit', 'create_permission_version', permissionArn=arn, policyTemplate=template(['ssm:DescribeParameters', 'ssm:GetParameterHistory']), clientToken=prefix+'-version-over-limit')
        call('default-before-highest-delete', 'set_default_permission_version', required=True, permissionArn=arn, permissionVersion=1)
        call('delete-highest-version', 'delete_permission_version', required=True, permissionArn=arn, permissionVersion=int(newest['permission']['version']))
        call('duplicate-deleted-template', 'create_permission_version', permissionArn=arn, policyTemplate=template(['ssm:DescribeParameters', 'ssm:GetParameter']), clientToken=prefix+'-duplicate-deleted')
        evidence['complete'] = True
    except BaseException as error:
        evidence['probe_failure'] = {'type':type(error).__name__, 'message':str(error)}
        raise
    finally:
        if arn is not None:
            try:
                client.delete_permission(permissionArn=arn)
                evidence['cleanup'].append({'operation':'DeletePermission','code':'Success','arn':arn})
                deadline = time.monotonic()+60
                while True:
                    detail = client.get_permission(permissionArn=arn)['permission']
                    if detail['status'] == 'DELETED':
                        evidence['cleanup'].append({'operation':'GetPermission','status':'DELETED','arn':arn})
                        break
                    if time.monotonic() >= deadline:
                        raise RuntimeError('Owned permission deletion did not settle')
                    time.sleep(1)
            except ClientError as error:
                evidence['cleanup'].append({'operation':'Cleanup','code':error.response['Error']['Code'],'arn':arn})
                if error.response['Error']['Code'] not in {'UnknownResourceException','ResourceArnNotFoundException'}:
                    raise
        save()
        print(json.dumps({'output':str(args.output),'complete':evidence['complete'],'cleanup':evidence['cleanup']}))


if __name__ == '__main__':
    main()
