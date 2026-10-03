#!/usr/bin/env python3
"""Capture cheap native SES classic controls/errors; delete only exact owned IDs."""
import argparse
import base64
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import time
import uuid

from aws_cli import call, observe


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True)
    parser.add_argument('--region', default='us-east-1')
    parser.add_argument("--account", required=True)
    parser.add_argument('--skip-iam', action='store_true')
    args = parser.parse_args()
    if any(key.startswith('AWS_ENDPOINT_URL') for key in os.environ):
        raise SystemExit('Native capture refuses endpoint overrides')
    env = dict(os.environ, AWS_DEFAULT_REGION=args.region, AWS_REGION=args.region,
               AWS_PAGER='', AWS_MAX_ATTEMPTS='1')
    caller = call('sts', 'get-caller-identity', env=env)
    if caller['Account'] != args.account:
        raise SystemExit('Unexpected native account; no mutations attempted')
    prefix = 'stackd-ses-classic-' + uuid.uuid4().hex[:12]
    sender = prefix + '@example.invalid'
    domain = prefix + '.example.invalid'
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    if output.exists():
        raise SystemExit('Refusing to overwrite a native capture')
    report = {
        'captured_at': datetime.now(timezone.utc).isoformat(), 'region': args.region,
        'caller': caller, 'prefix': prefix,
        'sources': ['https://docs.aws.amazon.com/ses/latest/APIReference/API_Operations.html',
                    'https://docs.aws.amazon.com/service-authorization/latest/reference/list_amazonses.html',
                    'https://docs.aws.amazon.com/ses/latest/dg/control-user-access.html#iam-and-ses-examples-access-specific-ses-api-version'],
        'safety': 'Only UUID-owned identities/templates/configuration/role; reserved example.invalid sender; simulator recipients only. No account-wide sending settings changed.',
        'calls': [], 'cleanup': [], 'limits': [
            'No verified native sender: successful delivery, SMTP, MIME and re-verification of an already-verified identity are not native-calibrated.',
            'AWS CLI transport does not retain request IDs here; no request-ID-correlated native CloudTrail audit evidence.'],
    }
    owned = []

    def save():
        output.write_text(json.dumps(report, indent=2) + '\n')

    def capture(label, operation, parameters=None, *, service='ses', environment=None):
        observation = observe(service, operation, parameters, environment or env, paginate=False)
        retained = dict(observation)
        if service == 'sts' and observation['code'] == 'Success':
            retained['output'] = {key: value for key, value in observation['output'].items() if key != 'Credentials'}
        if operation == 'list-verified-email-addresses' and observation['code'] == 'Success':
            retained['output'] = {'VerifiedEmailAddresses': [
                value for value in observation['output'].get('VerifiedEmailAddresses', []) if value == sender]}
            retained['projection'] = 'Only exact owned address retained from list'
        if observation['code'] == 'ParamValidation':
            retained['observation_source'] = 'AWS CLI validation; no native service request'
            report['limits'].append(label + ': CLI rejected operation/input before sending')
        report['calls'].append({'label': label, 'service': service, 'operation': operation,
                                'parameters': parameters or {}, **retained})
        save()
        print(label, observation['code'], flush=True)
        return observation

    def success(label, operation, parameters, *, service='ses'):
        observation = capture(label, operation, parameters, service=service)
        if observation['code'] != 'Success':
            raise RuntimeError(f'{label}: {observation}')
        return observation['output']

    template = {'TemplateName': prefix, 'SubjectPart': 'Hello {{name}}',
                'TextPart': 'Hello {{name}}', 'HtmlPart': '<b>{{name}}</b>'}
    destination = {'ToAddresses': ['success@simulator.amazonses.com']}
    simple = {'Source': sender, 'Destination': destination,
              'Message': {'Subject': {'Data': 'Undeliverable native validation'},
                          'Body': {'Text': {'Data': 'Reserved invalid sender; simulator recipient.'}}}}
    raw_bytes = (f'From: {sender}\r\nTo: success@simulator.amazonses.com\r\n'
                 'Subject: Undeliverable raw validation\r\nMIME-Version: 1.0\r\n'
                 'Content-Type: text/plain; charset=UTF-8\r\n\r\nNo delivery.\r\n').encode()
    raw = {'Source': sender, 'RawMessage': {'Data': base64.b64encode(raw_bytes).decode()}}
    templated = {'Source': sender, 'Destination': destination, 'Template': prefix,
                 'TemplateData': '{"name":"Native"}'}
    bulk = {'Source': sender, 'Template': prefix, 'DefaultTemplateData': '{"name":"Native"}',
            'Destinations': [{'Destination': destination}]}
    arn = f'arn:aws:ses:{args.region}:{caller["Account"]}:identity/{sender}'
    valid_policy = {'Version': '2012-10-17', 'Statement': [{'Effect': 'Allow',
                    'Principal': {'AWS': caller['Account']}, 'Action': 'ses:SendEmail', 'Resource': arn}]}
    try:
        missing = capture('missing-template-get', 'get-template', {'TemplateName': prefix})
        if missing['code'] != 'TemplateDoesNotExist':
            raise RuntimeError('Template absence not established; refusing mutation')
        capture('missing-template-update', 'update-template', {'Template': template})
        capture('missing-template-delete', 'delete-template', {'TemplateName': prefix})
        missing = capture('missing-configuration-get', 'describe-configuration-set', {'ConfigurationSetName': prefix})
        if missing['code'] != 'ConfigurationSetDoesNotExist':
            raise RuntimeError('Configuration absence not established; refusing mutation')
        capture('missing-configuration-delete', 'delete-configuration-set', {'ConfigurationSetName': prefix})
        before = success('missing-identities', 'get-identity-verification-attributes', {'Identities': [sender, domain]})
        if before.get('VerificationAttributes'):
            raise RuntimeError('Generated native identity already exists')
        capture('missing-policy-list', 'list-identity-policies', {'Identity': sender})
        capture('missing-policy-get', 'get-identity-policies', {'Identity': sender, 'PolicyNames': ['owned']})
        capture('missing-policy-delete', 'delete-identity-policy', {'Identity': sender, 'PolicyName': 'owned'})
        success('create-template', 'create-template', {'Template': template}); owned.append(('template', prefix))
        capture('duplicate-template', 'create-template', {'Template': template})
        success('create-configuration', 'create-configuration-set', {'ConfigurationSet': {'Name': prefix}}); owned.append(('configuration', prefix))
        capture('duplicate-configuration', 'create-configuration-set', {'ConfigurationSet': {'Name': prefix}})
        success('verify-email', 'verify-email-identity', {'EmailAddress': sender}); owned.append(('identity', sender))
        capture('repeat-verify-email', 'verify-email-identity', {'EmailAddress': sender})
        capture('legacy-repeat-verify-email', 'verify-email-address', {'EmailAddress': sender})
        capture('identity-case-lookup', 'get-identity-verification-attributes', {'Identities': [sender, sender.upper()]})
        capture('list-verified-emails', 'list-verified-email-addresses')
        success('verify-domain', 'verify-domain-identity', {'Domain': domain}); owned.append(('identity', domain))
        capture('pending-identities', 'get-identity-verification-attributes', {'Identities': [sender, domain]})
        capture('v2-duplicate-pending-identity', 'create-email-identity', {'EmailIdentity': sender}, service='sesv2')
        capture('v2-update-missing-policy', 'update-email-identity-policy', {'EmailIdentity': sender, 'PolicyName': 'owned', 'Policy': json.dumps(valid_policy)}, service='sesv2')
        capture('pending-policy-get-absent', 'get-identity-policies', {'Identity': sender, 'PolicyNames': ['absent']})
        capture('pending-policy-delete-absent', 'delete-identity-policy', {'Identity': sender, 'PolicyName': 'absent'})
        capture('policy-invalid-json', 'put-identity-policy', {'Identity': sender, 'PolicyName': 'invalid', 'Policy': '{'})
        wrong_resource = json.loads(json.dumps(valid_policy)); wrong_resource['Statement'][0]['Resource'] = arn + '-other'
        capture('policy-wrong-resource', 'put-identity-policy', {'Identity': sender, 'PolicyName': 'invalid', 'Policy': json.dumps(wrong_resource)})
        wrong_principal = json.loads(json.dumps(valid_policy)); wrong_principal['Statement'][0]['Principal'] = {'AWS': 'not-a-principal'}
        capture('policy-invalid-principal', 'put-identity-policy', {'Identity': sender, 'PolicyName': 'invalid', 'Policy': json.dumps(wrong_principal)})
        capture('policy-put', 'put-identity-policy', {'Identity': sender, 'PolicyName': 'owned', 'Policy': json.dumps(valid_policy)})
        capture('policy-overwrite', 'put-identity-policy', {'Identity': sender, 'PolicyName': 'owned', 'Policy': json.dumps(valid_policy)})
        capture('policy-list', 'list-identity-policies', {'Identity': sender})
        capture('policy-get', 'get-identity-policies', {'Identity': sender, 'PolicyNames': ['owned', 'absent']})
        capture('v2-duplicate-policy', 'create-email-identity-policy', {'EmailIdentity': sender, 'PolicyName': 'owned', 'Policy': json.dumps(valid_policy)}, service='sesv2')
        capture('simple-unverified', 'send-email', simple)
        capture('simple-empty-body', 'send-email', dict(simple, Message={'Subject': {'Data': 'Validation'}, 'Body': {}}))
        capture('simple-malformed-address', 'send-email', dict(simple, Destination={'ToAddresses': ['not-an-address']}))
        capture('simple-missing-configuration', 'send-email', dict(simple, ConfigurationSetName=prefix + '-missing'))
        capture('raw-unverified', 'send-raw-email', raw)
        capture('raw-malformed', 'send-raw-email', {'RawMessage': {'Data': base64.b64encode(b'malformed').decode()}})
        capture('template-unverified', 'send-templated-email', templated)
        capture('template-missing', 'send-templated-email', dict(templated, Template=prefix + '-missing'))
        capture('template-bad-json', 'send-templated-email', dict(templated, TemplateData='{'))
        capture('bulk-unverified', 'send-bulk-templated-email', bulk)
        capture('bulk-missing-template', 'send-bulk-templated-email', dict(bulk, Template=prefix + '-missing'))
        capture('bulk-bad-json', 'send-bulk-templated-email', dict(bulk, DefaultTemplateData='{'))
        if not args.skip_iam:
            trust = {'Version': '2012-10-17', 'Statement': [{'Effect': 'Allow', 'Principal': {'AWS': caller['Arn']}, 'Action': 'sts:AssumeRole'}]}
            role = capture('create-owned-role', 'create-role', {'RoleName': prefix, 'AssumeRolePolicyDocument': json.dumps(trust)}, service='iam')
            if role['code'] == 'Success':
                owned.append(('role', prefix))
                base_policy = {'Version': '2012-10-17', 'Statement': [{'Effect': 'Allow', 'Action': ['ses:SendEmail', 'ses:SendRawEmail', 'ses:SendTemplatedEmail', 'ses:SendBulkTemplatedEmail'], 'Resource': '*'}]}
                success('role-allow-sending', 'put-role-policy', {'RoleName': prefix, 'PolicyName': 'owned', 'PolicyDocument': json.dumps(base_policy)}, service='iam')
                sessions = {}
                modes = [('unconditional', None), ('2010-12-01', {'StringEquals': {'ses:ApiVersion': '2010-12-01'}}),
                         ('2019-09-27', {'StringEquals': {'ses:ApiVersion': '2019-09-27'}}),
                         ('1', {'StringEquals': {'ses:ApiVersion': '1'}}),
                         ('2', {'StringEquals': {'ses:ApiVersion': '2'}}),
                         ('version-absent', {'Null': {'ses:ApiVersion': 'true'}})]
                for mode, condition in modes:
                    statement = {'Effect': 'Allow', 'Action': 'ses:SendEmail', 'Resource': '*'}
                    if condition is not None:
                        statement['Condition'] = condition
                    session_policy = {'Version': '2012-10-17', 'Statement': [statement]}
                    for attempt in range(12):
                        assumed = capture(f'assume-{mode}-{attempt}', 'assume-role', {
                            'RoleArn': role['output']['Role']['Arn'], 'RoleSessionName': 'classic-' + mode,
                            'DurationSeconds': 900, 'Policy': json.dumps(session_policy)}, service='sts')
                        if assumed['code'] != 'AccessDenied':
                            break
                        time.sleep(5)
                    if assumed['code'] != 'Success':
                        report['limits'].append(f'STS {mode} session unavailable: {assumed["code"]}')
                        continue
                    credentials = assumed['output']['Credentials']
                    scoped = dict(env, AWS_ACCESS_KEY_ID=credentials['AccessKeyId'],
                                  AWS_SECRET_ACCESS_KEY=credentials['SecretAccessKey'], AWS_SESSION_TOKEN=credentials['SessionToken'])
                    sessions[mode] = scoped
                    if mode == 'unconditional':
                        for attempt in range(12):
                            ready = capture(f'iam-unconditional-readiness-{attempt}', 'send-email', simple, environment=scoped)
                            if ready['code'] != 'AccessDenied':
                                break
                            time.sleep(5)
                        if ready['code'] != 'MessageRejected':
                            report['limits'].append('Unconditional send never reached unverified-sender validation; IAM comparisons inconclusive')
                    for label, operation, parameters in [('simple', 'send-email', simple), ('raw', 'send-raw-email', raw),
                                                         ('template', 'send-templated-email', templated), ('bulk', 'send-bulk-templated-email', bulk)]:
                        capture(f'iam-{mode}-{label}', operation, parameters, environment=scoped)
                    modern = {'FromEmailAddress': sender, 'Destination': destination,
                              'Content': {'Simple': simple['Message']}}
                    capture(f'iam-{mode}-v2-simple', 'send-email', modern, service='sesv2', environment=scoped)
                if 'unconditional' in sessions:
                    deny = {'Version': '2012-10-17', 'Statement': [{'Effect': 'Deny', 'Action': 'ses:*', 'Resource': '*'}]}
                    success('current-role-deny', 'put-role-policy', {'RoleName': prefix, 'PolicyName': 'owned', 'PolicyDocument': json.dumps(deny)}, service='iam')
                    # Record propagation until the already-issued unconditional session
                    # actually sees the current role's explicit denial.
                    for attempt in range(12):
                        denied = capture(f'current-role-denial-{attempt}', 'send-email', simple, environment=sessions['unconditional'])
                        if denied['code'] in ('AccessDenied', 'AccessDeniedException'):
                            break
                        time.sleep(5)
            else:
                report['limits'].append('Native role creation unavailable: ' + role['code'])
        else:
            report['limits'].append('IAM native probes explicitly skipped')
    except Exception as error:
        report['failure'] = {'type': type(error).__name__, 'message': str(error)}
        raise
    finally:
        for kind, name in reversed(owned):
            try:
                if kind == 'role':
                    capture('cleanup-role-policy', 'delete-role-policy', {'RoleName': name, 'PolicyName': 'owned'}, service='iam')
                    removed = capture('cleanup-role', 'delete-role', {'RoleName': name}, service='iam')
                    absent = capture('cleanup-role-absent', 'get-role', {'RoleName': name}, service='iam')
                    verified = absent['code'] == 'NoSuchEntity'
                elif kind == 'identity':
                    removed = capture('cleanup-identity-' + name, 'delete-identity', {'Identity': name})
                    absent = capture('cleanup-identity-absent-' + name, 'get-identity-verification-attributes', {'Identities': [name]})
                    verified = absent['code'] == 'Success' and absent['output'].get('VerificationAttributes', {}) == {}
                elif kind == 'template':
                    removed = capture('cleanup-template', 'delete-template', {'TemplateName': name})
                    absent = capture('cleanup-template-absent', 'get-template', {'TemplateName': name})
                    verified = absent['code'] == 'TemplateDoesNotExist'
                else:
                    removed = capture('cleanup-configuration', 'delete-configuration-set', {'ConfigurationSetName': name})
                    absent = capture('cleanup-configuration-absent', 'describe-configuration-set', {'ConfigurationSetName': name})
                    verified = absent['code'] == 'ConfigurationSetDoesNotExist'
                report['cleanup'].append({'kind': kind, 'name': name, 'delete_code': removed['code'], 'absence_verified': verified})
            except Exception as error:
                report['cleanup'].append({'kind': kind, 'name': name, 'error': str(error)})
            save()
        save()
    if not all(row.get('absence_verified') for row in report['cleanup']):
        raise RuntimeError('Exact-owned native cleanup incomplete; inspect capture')


if __name__ == '__main__':
    main()
