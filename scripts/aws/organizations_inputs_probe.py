#!/usr/bin/env python3
"""Capture Organizations JSON validation on one owned OU and unattached policy."""
import argparse
import datetime
import json
from pathlib import Path
import uuid
import time

from iam_conditions_probe import require
from signed_requests import signed_post


def probe_parser(filename=None, *, output_help="Capture path (default: .stackd/probes/iam/<capture>.json)"):
    parser = argparse.ArgumentParser(description="Capture native AWS Organizations behavior.")
    parser.add_argument("--account", required=True, help="Expected 12-digit AWS caller account ID")
    parser.add_argument("--output", type=Path,
                        default=Path(".stackd/probes/iam") / filename if filename else None,
                        help=output_help)
    return parser


def verified_account(account):
    if len(account) != 12 or not account.isascii() or not account.isdigit():
        raise ValueError("--account must be a 12-digit AWS account ID")
    owner = require("sts", "get-caller-identity", {})["Account"]
    if owner != account:
        raise RuntimeError(f"Expected AWS account {account}, got {owner}")
    return owner


def capture_path(output):
    path = Path(output)
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


def call(action, parameters):
    response = signed_post('organizations.us-east-1.amazonaws.com', 'organizations',
                           json.dumps(parameters).encode(), {
                               'content-type': 'application/x-amz-json-1.1',
                               'x-amz-target': 'AWSOrganizationsV20161128.' + action})
    output = json.loads(response.body or '{}')
    return {'code': output.get('__type', 'Success').split('#')[-1], 'status': response.status, 'output': output}


def required(action, parameters):
    result = call(action, parameters)
    if result['code'] != 'Success':
        raise RuntimeError(action + ': ' + result['code'])
    return result['output']


def capture_paths(root, prefix, account):
    owned = []
    try:
        parent = required('CreateOrganizationalUnit', {'ParentId': root, 'Name': prefix + '-parent'})['OrganizationalUnit']
        owned.append(parent['Id'])
        child = required('CreateOrganizationalUnit', {'ParentId': parent['Id'], 'Name': prefix + '-child'})['OrganizationalUnit']
        owned.append(child['Id'])
        organization = required('DescribeOrganization', {})['Organization']['Id']
        replacements = {organization: 'ORGANIZATION_ID', root: 'ROOT_ID', account: 'ACCOUNT_ID',
                        parent['Id']: 'PARENT_ID', child['Id']: 'CHILD_ID'}
        def paths(record):
            text = json.dumps({k: v for k, v in record.items() if k in ['Path', 'Paths', 'Status', 'State']})
            for actual, label in replacements.items(): text = text.replace(actual, label)
            return json.loads(text)
        result = {'parent_create': paths(parent), 'child_create': paths(child),
                  'child_describe': paths(required('DescribeOrganizationalUnit', {'OrganizationalUnitId': child['Id']})['OrganizationalUnit']),
                  'child_list': paths(required('ListOrganizationalUnitsForParent', {'ParentId': parent['Id']})['OrganizationalUnits'][0]),
                  'account_describe': paths(required('DescribeAccount', {'AccountId': account})['Account'])}
        for label, action, parameters in [('account_list', 'ListAccounts', {}), ('account_list_for_parent', 'ListAccountsForParent', {'ParentId': root})]:
            for record in required(action, parameters)['Accounts']:
                if record['Id'] == account: result[label] = paths(record)
        return result
    finally:
        for unit in reversed(owned): required('DeleteOrganizationalUnit', {'OrganizationalUnitId': unit})


def capture_responses(unit, policy, prefix, content):
    required('UpdateOrganizationalUnit', {'OrganizationalUnitId': unit, 'Name': prefix})
    required('UpdatePolicy', {'PolicyId': policy, 'Name': prefix, 'Description': 'initial'})
    def normalize(value):
        if isinstance(value, dict):
            return {key: ('RESOURCE_' + key.upper() if key in ['Id', 'Arn', 'Path'] else normalize(item)) for key, item in value.items()}
        if isinstance(value, list): return [normalize(item) for item in value]
        if isinstance(value, str): return value.replace(prefix, 'OWNED_NAME')
        return value
    rows, delayed = [], []
    for action, fields in [('UpdateOrganizationalUnit', {}), ('UpdateOrganizationalUnit', {'Name': ' '}),
                           ('UpdatePolicy', {}), ('UpdatePolicy', {'Description': ''}),
                           ('UpdatePolicy', {'Name': 'changed', 'Description': 'next'}), ('UpdatePolicy', {'Content': content})]:
        selector = {'OrganizationalUnitId': unit} if action == 'UpdateOrganizationalUnit' else {'PolicyId': policy}
        result = call(action, dict(selector, **fields))
        rows.append({'action': action, 'input': fields, 'code': result['code'], 'output': normalize(result['output'])})
        if fields == {'Name': ' '} or fields == {'Description': ''}:
            response = result['output'].get('OrganizationalUnit', result['output'].get('Policy', {}).get('PolicySummary', {}))
            time.sleep(3)
            state = required('DescribeOrganizationalUnit', selector)['OrganizationalUnit'] if action == 'UpdateOrganizationalUnit' else required('DescribePolicy', selector)['Policy']['PolicySummary']
            delayed.append(normalize({'action': action, 'code': result['code'], 'returned_name': response.get('Name'), 'returned_description': response.get('Description'),
                                      'name_after_3s': state['Name'], 'description_after_3s': state.get('Description')}))
    return rows, delayed


def main():
    args = probe_parser("organizations_inputs.json").parse_args()
    account = verified_account(args.account)
    prefix = 'stackd-org-inputs-' + uuid.uuid4().hex[:12]
    root = required('ListRoots', {})['Roots'][0]['Id']
    cleanup = []
    capture = {'source': 'Signed AWS Organizations JSON requests on an owned OU and unattached SCP',
               'retrieved_at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
               'scope': 'Update name/description validation, optional field presence, tag atomicity and read-only page controls. No accounts moved, account settings changed or SCPs attached.',
               'observations': [], 'cleanup': False}
    try:
        unit = required('CreateOrganizationalUnit', {'ParentId': root, 'Name': prefix})['OrganizationalUnit']['Id']
        cleanup.append(('DeleteOrganizationalUnit', {'OrganizationalUnitId': unit}))
        content = '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}'
        policy = required('CreatePolicy', {'Name': prefix, 'Description': 'initial', 'Type': 'SERVICE_CONTROL_POLICY', 'Content': content})['Policy']['PolicySummary']['Id']
        cleanup.append(('DeletePolicy', {'PolicyId': policy}))
        cases = [('UpdateOrganizationalUnit', p) for p in [
            {'Name': 'changed'}, {}, {'Name': None}, {'Name': ''}, {'Name': ' '},
            {'Name': 'é' * 128}, {'Name': 'é' * 129}, {'Name': 'rejected', 'OrganizationalUnitId': 'invalid'},
            {'Name': 'ignored-selector', 'AccountId': 'invalid'}, {'Name': 'restored'}]]
        cases += [('UpdatePolicy', p) for p in [
            {'Description': 'é' * 512}, {}, {'Description': None}, {'Description': 'é' * 513},
            {'Description': ''}, {'Name': ' '}, {'Name': ''}, {'Name': prefix}, {'Content': ''}]]
        cases += [('TagResource', p) for p in [
            {'Tags': [{'Key': 'first', 'Value': 'value'}]}, {'Tags': []}, {'Tags': None}, {},
            {'Tags': [{'Key': 'rejected', 'Value': None}]}, {'Tags': [{'Key': 'rejected'}]},
            {'Tags': [{'Key': 'same', 'Value': 'a'}, {'Key': 'same', 'Value': 'b'}]},
            {'Tags': [{'Key': 'é' * 128, 'Value': 'é' * 256}]},
            {'Tags': [{'Key': 'valid', 'Value': 'pending'}, {'Key': 'é' * 129, 'Value': 'rejected'}]},
            {'Tags': [{'Key': 'first', 'Value': ''}]}]]
        cases += [('UntagResource', p) for p in [{'TagKeys': []}, {'TagKeys': None}, {}, {'TagKeys': ['first']}, {'TagKeys': ['missing']}]]
        cases += [('ListOrganizationalUnitsForParent', p) for p in [{'MaxResults': 0}, {'MaxResults': 21}, {'MaxResults': None}, {'MaxResults': 1}, {'NextToken': ''}]]
        for action, parameters in cases:
            original = dict(parameters)
            if action == 'UpdateOrganizationalUnit': parameters = {'OrganizationalUnitId': unit, **parameters}
            elif action == 'UpdatePolicy': parameters = {'PolicyId': policy, **parameters}
            elif action in ['TagResource', 'UntagResource']: parameters = {'ResourceId': unit, **parameters}
            else: parameters = {'ParentId': unit, **parameters}
            result = call(action, parameters)
            row = {'action': action, 'input': original, 'code': result['code'], 'status': result['status']}
            if result['code'] != 'Success': row['reason'] = result['output'].get('Reason', '')
            if action == 'UpdateOrganizationalUnit':
                row['name'] = required('DescribeOrganizationalUnit', {'OrganizationalUnitId': unit})['OrganizationalUnit']['Name']
            elif action == 'UpdatePolicy':
                policy_state = required('DescribePolicy', {'PolicyId': policy})['Policy']['PolicySummary']
                row['name'], row['description'] = policy_state['Name'], policy_state['Description']
            elif action in ['TagResource', 'UntagResource']:
                row['tags'] = sorted(required('ListTagsForResource', {'ResourceId': unit})['Tags'], key=lambda t: t['Key'])
            else: row['unit_count'] = len(result['output'].get('OrganizationalUnits', []))
            capture['observations'].append(row)
            print(f"{len(capture['observations'])}: {action} {result['code']}", flush=True)
        capture['hierarchy_paths'] = capture_paths(root, prefix, account)
        responses, delayed = capture_responses(unit, policy, prefix, content)
        captured_at = datetime.datetime.now(datetime.timezone.utc).isoformat()
        capture['response_followup'] = {'retrieved_at': captured_at, 'observations': responses, 'cleanup': True}
        capture['update_followup'] = {'retrieved_at': captured_at, 'observations': delayed, 'cleanup': True}
    finally:
        for action, parameters in reversed(cleanup): required(action, parameters)
        capture['cleanup'] = True
        data = json.dumps(capture, indent=2).replace(prefix, 'OWNED_NAME')
        capture_path(args.output).write_text(data + '\n')
        print('Deleted owned OU and unattached policy; wrote capture.', flush=True)


if __name__ == '__main__':
    main()
