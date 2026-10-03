#!/usr/bin/env python3
"""Local-only assembled SES classic/v2 MIME, IAM, Cognito and SQLite restart proof."""
import argparse
import base64
from datetime import datetime, timezone
import email
import email.policy
import email.utils
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import sqlite3
import subprocess
import urllib.parse
import urllib.request
import uuid

from aws_cli import result, run
from stackd_process import StackdProcess


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def policy(actions, *, version=None, effect='Allow'):
    statement = {'Effect': effect, 'Action': actions, 'Resource': '*'}
    if version is not None:
        statement['Condition'] = {'StringEquals': {'ses:ApiVersion': version}}
    return {'Version': '2012-10-17', 'Statement': [statement]}


class Workflow:
    def __init__(self, binary, sdk_binary, state):
        self.sdk_binary = str(Path(sdk_binary).resolve())
        self.state = Path(state).resolve()
        self.state.mkdir(parents=True, exist_ok=True)
        self.database = self.state / 'email.sqlite'
        require(not self.database.exists(), 'Refusing existing smoke state')
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0))
            port = sock.getsockname()[1]
        self.endpoint = f'http://127.0.0.1:{port}'
        self.account = '123456789012'
        self.region = 'us-east-1'
        self.env = {key: value for key, value in os.environ.items() if not key.startswith('AWS_')}
        self.env.update(AWS_ACCESS_KEY_ID='test', AWS_SECRET_ACCESS_KEY='test',
                        AWS_DEFAULT_REGION=self.region, AWS_REGION=self.region,
                        AWS_EC2_METADATA_DISABLED='true', AWS_PAGER='', AWS_MAX_ATTEMPTS='1',
                        AWS_CONFIG_FILE=os.devnull, AWS_SHARED_CREDENTIALS_FILE=os.devnull)
        self.controller = StackdProcess(self.state)
        self.command = [str(Path(binary).resolve()), '-listen', f'127.0.0.1:{port}',
                        '-public-endpoint', self.endpoint, '-account-id', self.account,
                        '-database', str(self.database), '-clock-start', datetime.now(timezone.utc).isoformat()]
        self.prefix = 'classic-' + uuid.uuid4().hex[:12]
        self.sender = self.prefix + '@example.invalid'
        self.recipient = 'success@simulator.amazonses.com'
        self.owned = []
        self.report = {'endpoint': self.endpoint, 'prefix': self.prefix, 'observations': {},
                       'calls': [], 'controllers': self.controller.runs, 'cleanup': [],
                       'limits': ['Local RFC 5322 capture, not Internet SMTP delivery.',
                                  'Read-only SQLite inspection proves retained envelope separately from MIME headers.']}

    def cli(self, service, operation, parameters=None, *, environment=None, codes=('Success',)):
        # Every invocation supplies an explicit loopback endpoint. Ambient AWS
        # profiles/credentials/endpoints are removed; there is no native fallback.
        observed = result(run(service, operation, parameters, environment or self.env,
                              options=['--endpoint-url', self.endpoint, '--cli-connect-timeout', '3',
                                       '--cli-read-timeout', '30', '--no-paginate']))
        self.report['calls'].append({'service': service, 'operation': operation, 'code': observed['code']})
        require(observed['code'] in codes, f'{service}:{operation}: {observed}')
        return observed.get('output', observed)

    def reject(self, service, operation, parameters, *, environment=None, codes=('AccessDenied',)):
        before = set(self.messages())
        observed = self.cli(service, operation, parameters, environment=environment, codes=codes)
        require(set(self.messages()) == before, f'{operation} rejection emitted email')
        return observed['code']

    def start(self):
        self.controller.start(self.command, self.endpoint, environment=self.env)

    def control(self, path, data=b''):
        request = urllib.request.Request(self.endpoint + path, data=data, headers={'Content-Type': 'application/json'})
        with urllib.request.urlopen(request, timeout=30) as response:
            return response.read()

    def messages(self):
        self.control('/_stackd/jobs/drain?limit=1024')
        return {path: email.message_from_bytes(path.read_bytes(), policy=email.policy.default)
                for path in Path(str(self.database) + '.ses').rglob('*.eml')}

    @staticmethod
    def text(message):
        body = message.get_body(preferencelist=('plain', 'html'))
        return body.get_content() if body else ''

    @staticmethod
    def addresses(message, header):
        return [address for _, address in email.utils.getaddresses(message.get_all(header, []))]

    def find(self, subject, recipient=None):
        rows = [(path, message) for path, message in self.messages().items()
                if str(message['Subject']) == subject and (recipient is None or self.addresses(message, 'To') == [recipient])]
        require(len(rows) == 1, f'Expected one capture for {subject!r}/{recipient!r}, got {len(rows)}')
        return rows[0]

    def verify(self, address):
        _, message = self.find('Amazon SES Email Address Verification Request', address)
        link = re.search(r'https?://[^\s<>]+', self.text(message))
        require(link is not None, 'Missing captured verification link')
        require(urllib.parse.urlsplit(link[0]).netloc == urllib.parse.urlsplit(self.endpoint).netloc,
                'Verification link escaped local endpoint')
        with urllib.request.urlopen(link[0], timeout=10) as response:
            require(response.status == 200, 'Verification link failed')
        classic = self.cli('ses', 'get-identity-verification-attributes', {'Identities': [address]})
        modern = self.cli('sesv2', 'get-email-identity', {'EmailIdentity': address})
        require(classic['VerificationAttributes'][address]['VerificationStatus'] == 'Success' and
                modern['VerifiedForSendingStatus'], 'Classic/v2 identity verification diverged')

    def envelope(self, message_id, account=None):
        with sqlite3.connect(self.database.as_uri() + '?mode=ro', uri=True) as connection:
            rows = connection.execute('SELECT a.kind,a.address FROM sesv2_message_addresses a '
                                      'JOIN sesv2_messages m ON m.arn=a.arn '
                                      'WHERE m.account_id=? AND m.region=? AND m.id=? ORDER BY a.kind,a.position',
                                      (account or self.account, self.region, message_id)).fetchall()
        return {kind: [email.utils.parseaddr(address)[1] for row_kind, address in rows if row_kind == kind]
                for kind in ('to', 'cc', 'bcc', 'reply')}

    def capture(self, response, subject, expected_text, *, bcc=(), envelope=None, account=None):
        message_id = response['MessageId']
        path, mime = self.find(subject)
        require(path.stem == message_id, 'Returned MessageId does not identify actual MIME')
        require(self.text(mime).strip() == expected_text, f'MIME body mismatch for {subject}')
        require(mime['Bcc'] is None, 'BCC leaked into RFC 5322 headers')
        retained = self.envelope(message_id, account)
        require(retained['bcc'] == list(bcc), f'BCC envelope lost: {retained}')
        if envelope is not None:
            require(retained == envelope, f'Explicit raw envelope mismatch: {retained}')
        else:
            require(retained['to'] == [self.recipient], f'Accepted recipient envelope lost: {retained}')
        observation = {'message_id': message_id, 'path': str(path), 'sha256': hashlib.sha256(path.read_bytes()).hexdigest(),
                       'subject': subject, 'envelope': retained}
        self.report['observations'][subject] = observation
        return observation

    def role_policy(self, document):
        self.cli('iam', 'put-role-policy', {'RoleName': self.prefix, 'PolicyName': 'sending', 'PolicyDocument': json.dumps(document)})

    def sdk(self, phase):
        completed = subprocess.run([self.sdk_binary, '-endpoint', self.endpoint, '-sender', self.sender,
                                    '-template', self.prefix, '-config', self.prefix, '-phase', phase],
                                   env=self.env, capture_output=True, text=True, timeout=90, check=False)
        require(completed.returncode == 0, 'Generated SDK proof failed: ' + completed.stderr)
        observed = json.loads(completed.stdout)
        for message in observed['messages']:
            retained = None
            if 'envelope_to' in message:
                retained = {'to': message['envelope_to'], 'cc': [], 'bcc': message.get('bcc') or [], 'reply': []}
            self.capture({'MessageId': message['message_id']}, message['subject'], message['text'],
                         bcc=message.get('bcc') or [], envelope=retained)
        self.report['observations']['sdk_' + phase] = observed

    def execute(self):
        self.start()
        self.cli('ses', 'verify-email-identity', {'EmailAddress': self.sender})
        self.owned.append(('identity', self.sender))
        pending = self.cli('sesv2', 'get-email-identity', {'EmailIdentity': self.sender})
        require(not pending['VerifiedForSendingStatus'], 'New classic identity unexpectedly verified')
        simple = {'Source': self.sender, 'Destination': {'ToAddresses': [self.recipient],
                  'CcAddresses': ['bounce@simulator.amazonses.com'], 'BccAddresses': ['complaint@simulator.amazonses.com']},
                  'Message': {'Subject': {'Data': 'Classic simple café'}, 'Body': {'Text': {'Data': 'Readable classic simple'},
                              'Html': {'Data': '<p>Readable classic simple</p>'}}}}
        self.reject('ses', 'send-email', simple, codes=('MessageRejected',))
        self.verify(self.sender)
        second = self.prefix + '-v2@example.invalid'
        self.cli('sesv2', 'create-email-identity', {'EmailIdentity': second}); self.owned.append(('identity', second))
        self.verify(second)
        listed = self.cli('ses', 'list-identities', {'IdentityType': 'EmailAddress'})['Identities']
        require({self.sender, second} <= set(listed), 'Classic discovery lost verified v2 identity')
        self.report['observations']['bidirectional_verified_identities'] = True

        template = {'TemplateName': self.prefix, 'SubjectPart': 'Classic {{name}}', 'TextPart': 'Hello {{name}}, code {{code}}', 'HtmlPart': '<b>{{name}}</b>'}
        self.cli('ses', 'create-template', {'Template': template}); self.owned.append(('template', self.prefix))
        modern = self.cli('sesv2', 'get-email-template', {'TemplateName': self.prefix})
        require(modern['TemplateContent']['Text'] == template['TextPart'], 'Classic template missing from v2')
        self.cli('sesv2', 'update-email-template', {'TemplateName': self.prefix, 'TemplateContent': {
            'Subject': 'Classic {{name}}', 'Text': 'Hello {{name}}, code {{code}}', 'Html': '<strong>{{name}}</strong>'}})
        require(self.cli('ses', 'get-template', {'TemplateName': self.prefix})['Template']['HtmlPart'] == '<strong>{{name}}</strong>', 'V2 update absent in classic')
        self.cli('ses', 'create-configuration-set', {'ConfigurationSet': {'Name': self.prefix}}); self.owned.append(('configuration', self.prefix))
        require(self.cli('sesv2', 'get-configuration-set', {'ConfigurationSetName': self.prefix})['ConfigurationSetName'] == self.prefix, 'Classic configuration missing from v2')
        self.cli('sesv2', 'create-configuration-set', {'ConfigurationSetName': self.prefix + '-v2'}); self.owned.append(('configuration', self.prefix + '-v2'))
        require(self.cli('ses', 'describe-configuration-set', {'ConfigurationSetName': self.prefix + '-v2'})['ConfigurationSet']['Name'] == self.prefix + '-v2', 'V2 configuration missing from classic')
        self.cli('sesv2', 'put-email-identity-configuration-set-attributes', {'EmailIdentity': self.sender, 'ConfigurationSetName': self.prefix})
        self.report['observations']['bidirectional_templates_configuration_sets'] = True
        identity_policy = {'Version': '2012-10-17', 'Statement': [{'Effect': 'Allow', 'Principal': {'AWS': f'arn:aws:iam::{self.account}:root'},
                           'Action': 'ses:SendEmail', 'Resource': f'arn:aws:ses:{self.region}:{self.account}:identity/{self.sender}'}]}
        self.cli('ses', 'put-identity-policy', {'Identity': self.sender, 'PolicyName': 'shared', 'Policy': json.dumps(identity_policy)})
        modern_policies = self.cli('sesv2', 'get-email-identity-policies', {'EmailIdentity': self.sender})
        require(json.loads(modern_policies['Policies']['shared']) == identity_policy, 'Classic policy missing from v2')
        identity_policy['Statement'][0]['Action'] = ['ses:SendEmail', 'ses:SendRawEmail']
        self.cli('sesv2', 'update-email-identity-policy', {'EmailIdentity': self.sender, 'PolicyName': 'shared', 'Policy': json.dumps(identity_policy)})
        classic_policies = self.cli('ses', 'get-identity-policies', {'Identity': self.sender, 'PolicyNames': ['shared']})
        require(json.loads(classic_policies['Policies']['shared']) == identity_policy, 'V2 policy update missing from classic')
        self.report['observations']['bidirectional_identity_policy'] = True

        simple_capture = self.capture(self.cli('ses', 'send-email', simple), 'Classic simple café', 'Readable classic simple',
                                      bcc=['complaint@simulator.amazonses.com'],
                                      envelope={'to': [self.recipient], 'cc': ['bounce@simulator.amazonses.com'],
                                                'bcc': ['complaint@simulator.amazonses.com'], 'reply': []})
        _, simple_mime = self.find('Classic simple café')
        require(self.addresses(simple_mime, 'To') == [self.recipient] and self.addresses(simple_mime, 'Cc') == ['bounce@simulator.amazonses.com'],
                'Simple visible recipient headers differ from the requested recipients')
        require(simple_mime.get_body(preferencelist=('html',)).get_content().strip() == '<p>Readable classic simple</p>',
                'Simple HTML alternative lost')
        raw_bytes = (f'From: {self.sender}\r\nTo: {self.recipient}\r\nBcc: complaint@simulator.amazonses.com\r\n'
                     'Subject: Classic raw\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\nReadable classic raw\r\n').encode()
        raw = {'RawMessage': {'Data': base64.b64encode(raw_bytes).decode()}}
        self.capture(self.cli('ses', 'send-raw-email', raw), 'Classic raw', 'Readable classic raw', bcc=['complaint@simulator.amazonses.com'])
        explicit_raw = {'Source': self.sender, 'Destinations': ['bounce@simulator.amazonses.com'],
                        'RawMessage': {'Data': base64.b64encode(raw_bytes.replace(b'Classic raw', b'Classic raw explicit envelope')).decode()}}
        self.capture(self.cli('ses', 'send-raw-email', explicit_raw), 'Classic raw explicit envelope', 'Readable classic raw',
                     envelope={'to': ['bounce@simulator.amazonses.com'], 'cc': [], 'bcc': [], 'reply': []})
        _, explicit_mime = self.find('Classic raw explicit envelope')
        require(self.addresses(explicit_mime, 'To') == [self.recipient], 'Raw Destinations incorrectly rewrote visible MIME To')
        templated = {'Source': self.sender, 'Destination': {'ToAddresses': [self.recipient]}, 'Template': self.prefix,
                     'TemplateData': '{"name":"template","code":"654321"}'}
        self.capture(self.cli('ses', 'send-templated-email', templated), 'Classic template', 'Hello template, code 654321')
        bulk = {'Source': self.sender, 'Template': self.prefix, 'DefaultTemplateData': '{"name":"bulk","code":"123456"}',
                'Destinations': [{'Destination': {'ToAddresses': [self.recipient]}},
                                 {'Destination': {'ToAddresses': ['unverified@example.invalid']}},
                                 {'Destination': {'ToAddresses': [self.recipient]}, 'ReplacementTemplateData': '{"name":"broken"}'}]}
        before_bulk = set(self.messages())
        outcomes = self.cli('ses', 'send-bulk-templated-email', bulk)['Status']
        require([entry['Status'] for entry in outcomes] == ['Success', 'MessageRejected', 'Failed'], f'Unexpected bulk boundaries: {outcomes}')
        bulk_capture = self.capture(outcomes[0], 'Classic bulk', 'Hello bulk, code 123456')
        require(set(self.messages()) - before_bulk == {Path(bulk_capture['path'])}, 'Failed bulk entries emitted MIME')
        self.report['observations']['bulk_statuses'] = outcomes
        self.reject('ses', 'send-raw-email', {'RawMessage': {'Data': base64.b64encode(b'malformed').decode()}}, codes=('InvalidParameterValue',))
        self.sdk('before')

        trust = {'Version': '2012-10-17', 'Statement': [{'Effect': 'Allow', 'Principal': {'AWS': f'arn:aws:iam::{self.account}:root'}, 'Action': 'sts:AssumeRole'}]}
        role = self.cli('iam', 'create-role', {'RoleName': self.prefix, 'AssumeRolePolicyDocument': json.dumps(trust)})['Role']; self.owned.append(('role', self.prefix))
        self.role_policy(policy('ses:*', version='1'))
        credentials = self.cli('sts', 'assume-role', {'RoleArn': role['Arn'], 'RoleSessionName': 'classic-proof', 'DurationSeconds': 900})['Credentials']
        actor = dict(self.env, AWS_ACCESS_KEY_ID=credentials['AccessKeyId'], AWS_SECRET_ACCESS_KEY=credentials['SecretAccessKey'], AWS_SESSION_TOKEN=credentials['SessionToken'])
        version_send = json.loads(json.dumps(simple)); version_send['Message']['Subject']['Data'] = 'Classic version authority'
        self.capture(self.cli('ses', 'send-email', version_send, environment=actor), 'Classic version authority', 'Readable classic simple', bcc=['complaint@simulator.amazonses.com'])
        modern_send = {'FromEmailAddress': self.sender, 'Destination': {'ToAddresses': [self.recipient]},
                       'Content': {'Simple': {'Subject': {'Data': 'Denied v2 version'}, 'Body': {'Text': {'Data': 'Must not capture'}}}}}
        self.reject('sesv2', 'send-email', modern_send, environment=actor, codes=('AccessDeniedException',))
        recipients_policy = policy('ses:SendEmail', version='1')
        recipients_policy['Statement'][0]['Condition']['ForAllValues:StringEquals'] = {
            'ses:Recipients': [self.recipient, 'bounce@simulator.amazonses.com']}
        self.role_policy(recipients_policy)
        self.reject('ses', 'send-email', simple, environment=actor)
        allowed_recipients = json.loads(json.dumps(simple))
        del allowed_recipients['Destination']['BccAddresses']
        allowed_recipients['Message']['Subject']['Data'] = 'Classic BCC condition positive control'
        self.capture(self.cli('ses', 'send-email', allowed_recipients, environment=actor),
                     'Classic BCC condition positive control', 'Readable classic simple')
        self.report['observations']['bcc_recipient_iam_admission'] = True
        self.role_policy(policy('ses:SendEmail', version='1'))
        for operation, parameters in [('send-raw-email', raw), ('send-templated-email', templated), ('send-bulk-templated-email', bulk)]:
            self.reject('ses', operation, parameters, environment=actor)
        self.role_policy(policy('ses:*', effect='Deny'))
        self.reject('ses', 'send-email', simple, environment=actor)
        self.role_policy(policy('ses:SendEmail', version='2'))
        self.reject('ses', 'send-email', simple, environment=actor)
        modern_send['Content']['Simple']['Subject']['Data'] = 'V2 version authority'
        self.capture(self.cli('sesv2', 'send-email', modern_send, environment=actor), 'V2 version authority', 'Must not capture')
        self.role_policy(policy('ses:SendEmail', version='2010-12-01'))
        self.reject('ses', 'send-email', simple, environment=actor)
        self.role_policy(policy('ses:SendEmail', version='2019-09-27'))
        self.reject('sesv2', 'send-email', modern_send, environment=actor, codes=('AccessDeniedException',))
        self.report['observations']['current_role_action_and_api_version_admission'] = True

        for scope, environment in [('region', dict(self.env, AWS_REGION='us-west-2', AWS_DEFAULT_REGION='us-west-2')),
                                   ('account', dict(self.env, AWS_ACCESS_KEY_ID='210987654321'))]:
            self.reject('ses', 'send-email', simple, environment=environment, codes=('MessageRejected',))
            identities = self.cli('ses', 'get-identity-verification-attributes', {'Identities': [self.sender]}, environment=environment)
            require(identities.get('VerificationAttributes', {}) == {}, f'{scope} leaked identity')
            self.cli('ses', 'get-template', {'TemplateName': self.prefix}, environment=environment, codes=('TemplateDoesNotExist',))
            self.cli('ses', 'describe-configuration-set', {'ConfigurationSetName': self.prefix}, environment=environment, codes=('ConfigurationSetDoesNotExist',))
        self.report['observations']['account_and_region_isolation'] = True

        foreign_account = '210987654321'
        foreign = dict(self.env, AWS_ACCESS_KEY_ID=foreign_account)
        delegated_arn = f'arn:aws:ses:{self.region}:{self.account}:identity/{second}'
        delegated = {'Source': second, 'SourceArn': delegated_arn, 'Destination': {'ToAddresses': [self.recipient]},
                     'Message': {'Subject': {'Data': 'Classic delegated identity'}, 'Body': {'Text': {'Data': 'Shared policy delegation'}}}}
        self.reject('ses', 'send-email', delegated, environment=foreign)
        grant = {'Version': '2012-10-17', 'Statement': [{'Effect': 'Allow',
                 'Principal': {'AWS': f'arn:aws:iam::{foreign_account}:root'}, 'Action': 'ses:SendEmail', 'Resource': delegated_arn}]}
        self.cli('ses', 'put-identity-policy', {'Identity': second, 'PolicyName': 'delegation', 'Policy': json.dumps(grant)})
        self.capture(self.cli('ses', 'send-email', delegated, environment=foreign),
                     'Classic delegated identity', 'Shared policy delegation', account=foreign_account,
                     envelope={'to': [self.recipient], 'cc': [], 'bcc': [], 'reply': []})
        delegated_modern = {'FromEmailAddress': second, 'FromEmailAddressIdentityArn': delegated_arn,
                            'Destination': delegated['Destination'],
                            'Content': {'Simple': {'Subject': {'Data': 'V2 delegated identity'},
                                                  'Body': {'Text': {'Data': 'Shared policy delegation'}}}}}
        self.capture(self.cli('sesv2', 'send-email', delegated_modern, environment=foreign),
                     'V2 delegated identity', 'Shared policy delegation', account=foreign_account,
                     envelope={'to': [self.recipient], 'cc': [], 'bcc': [], 'reply': []})
        self.cli('ses', 'delete-identity-policy', {'Identity': second, 'PolicyName': 'delegation'})
        self.reject('ses', 'send-email', delegated, environment=foreign)
        self.reject('sesv2', 'send-email', delegated_modern, environment=foreign, codes=('AccessDeniedException',))
        self.report['observations']['cross_account_policy_grant_and_revocation'] = True

        pool = self.cli('cognito-idp', 'create-user-pool', {'PoolName': self.prefix, 'AutoVerifiedAttributes': ['email']})['UserPool']
        self.owned.append(('pool', pool['Id']))
        app = self.cli('cognito-idp', 'create-user-pool-client', {'UserPoolId': pool['Id'], 'ClientName': self.prefix,
                       'ExplicitAuthFlows': ['ALLOW_USER_PASSWORD_AUTH', 'ALLOW_REFRESH_TOKEN_AUTH']})['UserPoolClient']
        self.cli('cognito-idp', 'sign-up', {'ClientId': app['ClientId'], 'Username': 'classic-user', 'Password': 'FirstPassword1!',
                 'UserAttributes': [{'Name': 'email', 'Value': self.prefix + '-cognito@example.invalid'}]})
        _, verification = self.find('Your verification code')
        code = re.search(r'\d{6}', self.text(verification))[0]
        self.reject('cognito-idp', 'confirm-sign-up', {'ClientId': app['ClientId'], 'Username': 'classic-user', 'ConfirmationCode': 'bad-code'}, codes=('CodeMismatchException',))
        before_restart = {str(path): hashlib.sha256(path.read_bytes()).hexdigest() for path in self.messages()}
        self.controller.stop(); self.start()
        after_restart_hashes = {str(path): hashlib.sha256(path.read_bytes()).hexdigest() for path in self.messages()}
        require(after_restart_hashes == before_restart, 'Restart lost, changed or duplicated captured MIME')
        require(self.cli('sesv2', 'get-email-identity', {'EmailIdentity': self.sender})['VerifiedForSendingStatus'], 'Shared identity lost on restart')
        require(self.cli('ses', 'get-template', {'TemplateName': self.prefix})['Template']['TextPart'] == template['TextPart'], 'Template lost on restart')
        self.cli('ses', 'describe-configuration-set', {'ConfigurationSetName': self.prefix})
        after_restart = dict(templated, TemplateData='{"name":"after restart","code":"234567"}')
        self.capture(self.cli('ses', 'send-templated-email', after_restart), 'Classic after restart', 'Hello after restart, code 234567')
        self.sdk('after')
        self.cli('cognito-idp', 'confirm-sign-up', {'ClientId': app['ClientId'], 'Username': 'classic-user', 'ConfirmationCode': code})
        self.cli('cognito-idp', 'forgot-password', {'ClientId': app['ClientId'], 'Username': 'classic-user'})
        _, reset = self.find('Your password reset code')
        reset_code = re.search(r'\d{6}', self.text(reset))[0]
        self.cli('cognito-idp', 'confirm-forgot-password', {'ClientId': app['ClientId'], 'Username': 'classic-user',
                 'ConfirmationCode': reset_code, 'Password': 'SecondPassword2!'})
        tokens = self.cli('cognito-idp', 'initiate-auth', {'ClientId': app['ClientId'], 'AuthFlow': 'USER_PASSWORD_AUTH',
                         'AuthParameters': {'USERNAME': 'classic-user', 'PASSWORD': 'SecondPassword2!'}})['AuthenticationResult']
        user = self.cli('cognito-idp', 'get-user', {'AccessToken': tokens['AccessToken']})
        attributes = {row['Name']: row['Value'] for row in user['UserAttributes']}
        require(user['Username'] == 'classic-user' and attributes.get('email_verified') == 'true',
                'Retained Cognito verification/reset/login did not authenticate the verified user')
        self.reject('cognito-idp', 'initiate-auth', {'ClientId': app['ClientId'], 'AuthFlow': 'USER_PASSWORD_AUTH',
                    'AuthParameters': {'USERNAME': 'classic-user', 'PASSWORD': 'FirstPassword1!'}}, codes=('NotAuthorizedException',))
        self.report['observations']['cognito_retained_verification_reset_login'] = True
        self.report['observations']['restart_retained_sha256'] = before_restart
        self.report['observations']['first_message_sha256'] = simple_capture['sha256']
        self.report['observations']['captured_message_count'] = len(self.messages())

    def cleanup(self):
        for kind, name in reversed(self.owned):
            try:
                if kind == 'pool':
                    self.cli('cognito-idp', 'delete-user-pool', {'UserPoolId': name})
                    self.cli('cognito-idp', 'describe-user-pool', {'UserPoolId': name}, codes=('ResourceNotFoundException',))
                elif kind == 'role':
                    self.cli('iam', 'delete-role-policy', {'RoleName': name, 'PolicyName': 'sending'})
                    self.cli('iam', 'delete-role', {'RoleName': name})
                    self.cli('iam', 'get-role', {'RoleName': name}, codes=('NoSuchEntity',))
                elif kind == 'template':
                    self.cli('sesv2', 'delete-email-template', {'TemplateName': name})
                    self.cli('ses', 'get-template', {'TemplateName': name}, codes=('TemplateDoesNotExist',))
                elif kind == 'configuration':
                    self.cli('ses', 'delete-configuration-set', {'ConfigurationSetName': name})
                    self.cli('sesv2', 'get-configuration-set', {'ConfigurationSetName': name}, codes=('NotFoundException',))
                else:
                    self.cli('ses', 'delete-identity', {'Identity': name})
                    observed = self.cli('ses', 'get-identity-verification-attributes', {'Identities': [name]})
                    require(observed.get('VerificationAttributes', {}) == {}, 'Deleted identity still visible')
                    self.cli('sesv2', 'get-email-identity', {'EmailIdentity': name}, codes=('NotFoundException',))
                self.report['cleanup'].append({'kind': kind, 'name': name, 'absence_verified': True})
            except Exception as error:
                self.report['cleanup'].append({'kind': kind, 'name': name, 'error': str(error)})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', required=True)
    parser.add_argument('--sdk-binary', required=True)
    parser.add_argument('--state-directory', required=True)
    args = parser.parse_args()
    workflow = Workflow(args.binary, args.sdk_binary, args.state_directory)
    try:
        workflow.execute()
    except Exception as error:
        workflow.report['failure'] = {'type': type(error).__name__, 'message': str(error)}
        raise
    finally:
        try:
            if workflow.controller.process is not None and workflow.controller.process.poll() is None:
                workflow.cleanup()
        finally:
            try:
                workflow.controller.stop()
            finally:
                (workflow.state / 'evidence.json').write_text(json.dumps(workflow.report, indent=2) + '\n')
    require(all(row.get('absence_verified') for row in workflow.report['cleanup']), 'Exact-owned cleanup failed; inspect evidence.json')
    print(json.dumps(workflow.report, indent=2))


if __name__ == '__main__':
    main()
