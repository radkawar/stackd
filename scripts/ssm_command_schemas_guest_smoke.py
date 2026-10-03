#!/usr/bin/env python3
"""Customer schema 1.2/2.0 execution through the actual official guest agent."""
import hashlib
import json
import yaml
import ssm_managed_guest_smoke as guest


class CommandSchemasSmoke(guest.Smoke):
    def content(self, schema, text='one', fmt='JSON', multiple=False):
        inputs = {'runCommand': [f'printf "{text}:%s\\n" "{{{{ message }}}}"', 'exit {{ code }}'], 'timeoutSeconds': '{{ executionTimeout }}'}
        doc = {'schemaVersion': schema, 'description': 'official agent customer schema', 'parameters': {
            'message': {'type': 'String', 'default': 'hello', 'allowedPattern': '^[a-z-]+$', 'minChars': 2, 'maxChars': 30},
            'code': {'type': 'String', 'default': '0', 'allowedValues': ['0', '7']},
            'executionTimeout': {'type': 'String', 'default': '17'}}}
        if schema == '1.2':
            doc['runtimeConfig'] = {'aws:runShellScript': {'properties': [dict(inputs, id='first')]}}
            if multiple:
                doc['runtimeConfig']['aws:runShellScript']['properties'].append({'id': 'second', 'runCommand': ['printf "second-property\\n"'], 'timeoutSeconds': '70'})
        else:
            doc['mainSteps'] = [{'action': 'aws:runShellScript', 'name': 'shell', 'inputs': inputs}]
        return json.dumps(doc) if fmt == 'JSON' else yaml.safe_dump(doc, sort_keys=False)

    def create(self, suffix, schema, fmt='JSON', multiple=False):
        name = self.prefix + '-' + suffix
        content = self.content(schema, fmt=fmt, multiple=multiple)
        made = self.call('create-' + suffix, 'ssm', 'create_document', Name=name, Content=content, DocumentType='Command', DocumentFormat=fmt)
        self.owned.setdefault('schema_documents', []).append(name)
        assert made['DocumentDescription']['SchemaVersion'] == schema
        assert made['DocumentDescription']['Hash'] == hashlib.sha256(content.encode()).hexdigest()
        self.wait('document active', lambda: self.client('ssm').describe_document(Name=name), lambda r: r['Document']['Status'] == 'Active')
        got = self.call('get-' + suffix, 'ssm', 'get_document', Name=name, DocumentFormat=fmt)
        assert got['Content'] == content
        return name

    def run_document(self, label, name, schema, version='1', code='0', message='custom', text='one', restart=False, multiple=False):
        out = self.call(label, 'ssm', 'send_command', DocumentName=name, DocumentVersion=version, InstanceIds=[self.owned['instance']], Parameters={'message': [message], 'code': [code], 'executionTimeout': ['31']}, TimeoutSeconds=300)
        command = out['Command']
        assert (command['ExpiresAfter'] - command['RequestedDateTime']).total_seconds() == 331
        if restart:
            self.stop()
            self.start()
        plugin = 'aws:runShellScript' if schema == '1.2' else 'shell'
        result = self.result(label + '-result', command['CommandId'], plugin=plugin, seconds=300)
        assert result['Status'] == ('Success' if code == '0' else 'Failed'), result
        assert result['ResponseCode'] == int(code), result
        # The official agent inserts a separator between legacy property outputs.
        expected = text + ':' + message + '\n' + ('\nsecond-property\n' if multiple else '')
        assert result['StandardOutputContent'] == expected, result
        listed = self.call(label + '-plugin-names', 'ssm', 'list_command_invocations', CommandId=command['CommandId'], Details=True)
        assert [p['Name'] for p in listed['CommandInvocations'][0]['CommandPlugins']] == [plugin], listed
        return command['CommandId']

    def exercise(self):
        documents = {}
        for schema in ('1.2', '2.0', '2.2'):
            for fmt in ('JSON', 'YAML'):
                name = self.create(schema.replace('.', '') + '-' + fmt, schema, fmt)
                documents[(schema, fmt)] = name
                self.run_document(schema + fmt + '-success', name, schema)
                self.run_document(schema + fmt + '-failure', name, schema, code='7')
                self.expect(schema + fmt + '-constraint', 'InvalidParameters', 'ssm', 'send_command', DocumentName=name, InstanceIds=[self.owned['instance']], Parameters={'message': ['123']})
        legacy = documents[('1.2', 'JSON')]
        self.expect('legacy-update-denied', 'InvalidDocumentSchemaVersion', 'ssm', 'update_document', Name=legacy, Content=self.content('1.2', 'two'), DocumentVersion='$LATEST')
        self.expect('legacy-migration-denied', 'InvalidDocumentSchemaVersion', 'ssm', 'update_document', Name=legacy, Content=self.content('2.2', 'two'), DocumentVersion='$LATEST')
        modern = documents[('2.0', 'YAML')]
        self.call('update-modern-version', 'ssm', 'update_document', Name=modern, Content=self.content('2.0', 'two', 'YAML'), DocumentFormat='YAML', DocumentVersion='$LATEST')
        self.wait('version two active', lambda: self.client('ssm').describe_document(Name=modern, DocumentVersion='2'), lambda r: r['Document']['Status'] == 'Active')
        self.call('select-modern-default', 'ssm', 'update_document_default_version', Name=modern, DocumentVersion='2')
        self.run_document('modern-old-version', modern, '2.0', version='1')
        self.run_document('modern-default-version', modern, '2.0', version='$DEFAULT', text='two')
        self.run_document('legacy-restart', legacy, '1.2', restart=True)
        self.run_document('modern-latest-restart', modern, '2.0', version='$LATEST', text='two', restart=True)
        multi = self.create('legacy-properties', '1.2', multiple=True)
        self.run_document('legacy-multiple-properties', multi, '1.2', multiple=True)
        role = self.prefix + '-caller'
        trust = {'Version': '2012-10-17', 'Statement': [{'Effect': 'Allow', 'Principal': {'AWS': f'arn:aws:iam::{self.account}:root'}, 'Action': 'sts:AssumeRole'}]}
        arn = self.call('create-scoped-role', 'iam', 'create_role', RoleName=role, AssumeRolePolicyDocument=json.dumps(trust))['Role']['Arn']
        self.owned['caller_role'] = role
        policy = {'Version': '2012-10-17', 'Statement': [{'Effect': 'Allow', 'Action': ['ssm:GetDocument', 'ssm:SendCommand'], 'Resource': [f'arn:aws:ssm:{guest.REGION}:{self.account}:document/{legacy}', f'arn:aws:ec2:{guest.REGION}:{self.account}:instance/{self.owned["instance"]}']}]}
        self.call('set-scoped-policy', 'iam', 'put_role_policy', RoleName=role, PolicyName='command', PolicyDocument=json.dumps(policy))
        creds = self.client('sts').assume_role(RoleArn=arn, RoleSessionName='schema-authority')['Credentials']
        client = self.client('ssm', creds)
        self.call('scoped-document-read', 'ssm', 'get_document', client=client, Name=legacy)
        scoped = self.call('scoped-command-allowed', 'ssm', 'send_command', client=client, DocumentName=legacy, InstanceIds=[self.owned['instance']])
        assert self.result('scoped-command-output', scoped['Command']['CommandId'])['StandardOutputContent'] == 'one:hello\n'
        self.expect('scoped-other-document-read', 'AccessDeniedException', 'ssm', 'get_document', client=client, Name=modern)
        self.expect('scoped-other-document-send', 'AccessDeniedException', 'ssm', 'send_command', client=client, DocumentName=modern, InstanceIds=[self.owned['instance']])
        policy['Statement'][0]['Resource'] = [f'arn:aws:ssm:{guest.REGION}:{self.account}:document/{legacy}']
        self.call('revoke-current-node-authority', 'iam', 'put_role_policy', RoleName=role, PolicyName='command', PolicyDocument=json.dumps(policy))
        self.expect('scoped-node-send-denied', 'AccessDeniedException', 'ssm', 'send_command', client=client, DocumentName=legacy, InstanceIds=[self.owned['instance']])
        self.data['observations']['schema-proof'] = {'schemas': ['1.2', '2.0', '2.2'], 'formats': ['JSON', 'YAML'], 'official_agent_execution': True, 'legacy_single_plugin_multiple_properties': True, 'immutable_versions_and_controller_restart': True, 'current_scoped_iam': True, 'native_execution_calibration': 'Not performed; native capture measures admission and delivery expiry only.'}
        self.save()

    def cleanup(self):
        errors = []
        for name in self.owned.get('schema_documents', []):
            try:
                self.call('delete-schema-document', 'ssm', 'delete_document', Name=name)
                self.expect('schema-document-absent', 'InvalidDocument', 'ssm', 'describe_document', Name=name)
            except Exception as error:
                errors.append(str(error))
        self.data['schema_document_cleanup'] = {'errors': errors, 'absent': not errors}
        self.save()
        super().cleanup()
        if errors:
            raise RuntimeError('schema document cleanup incomplete: ' + json.dumps(errors))


if __name__ == '__main__':
    guest.Smoke = CommandSchemasSmoke
    guest.main()
