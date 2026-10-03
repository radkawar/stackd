#!/usr/bin/env python3
"""Capture KMS imported-material behavior with owned keys and OpenSSL wrapping."""
import base64
import datetime
import json
import os
import pathlib
import subprocess
import tempfile
import time

from aws_cli import call, observe as observe_cli


class Capture:
    def __init__(self, name="imports", *, account):
        os.environ.setdefault('AWS_DEFAULT_REGION', 'us-east-1')
        from aws_cli import require_account
        account = require_account(account)["Account"]
        self.path = pathlib.Path(__file__).resolve().parents[2] / ('.stackd/probes/kms/' + name + '.json')
        self.fixture = {'observed_at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
                        'source': 'Owned EXTERNAL KMS keys, synthetic key material and OpenSSL',
                        'observations': [], 'cleanup': [], 'capture_complete': False}
        self.owned = []
        self.replacements = {account: '111111111111'}

    def save(self):
        body = json.dumps(self.fixture, indent=2)
        for actual, replacement in self.replacements.items():
            body = body.replace(actual, replacement)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(body + '\n')

    def observe(self, case, operation, params=None, region='us-east-1'):
        row = {'case': case, 'operation': operation, 'region': region}
        safe = dict(params or {})
        for name in ['ImportToken', 'EncryptedKeyMaterial']:
            if name in safe:
                safe[name] = '<omitted>'
        row['input'] = safe
        row.update(observe_cli('kms', operation, params, dict(os.environ, AWS_DEFAULT_REGION=region), paginate=False))
        out = row.get("output")
        if out is not None:
            for field in ['KeyMetadata', 'ReplicaKeyMetadata']:
                if field in out and operation in ['create-key', 'replicate-key']:
                    metadata = out[field]
                    key = metadata['KeyId']
                    owned = (metadata['Arn'].split(':')[3], key)
                    if owned not in self.owned:
                        self.owned.append(owned)
                    if key not in self.replacements:
                        prefix = 'mrk-' if key.startswith('mrk-') else ''
                        self.replacements[key] = prefix + ('%032x' % len(self.owned) if prefix else '00000000-0000-0000-0000-%012d' % len(self.owned))
                    print('Owned key: ' + key + ' in ' + owned[0], flush=True)
            display = dict(out)
            if 'ImportToken' in display:
                display['ImportToken'] = '<omitted>'
            row.update(output=display)
        if row["code"] == 'ParamValidation':
            row['source'] = 'AWS CLI validation; request was not sent to AWS'
        if not case.endswith('_poll') or self.fixture['observations'][-1:] != [row]:
            self.fixture['observations'].append(row)
            self.save()
            print(case + ': ' + row['code'], flush=True)
        return out

    def create(self, name, spec='SYMMETRIC_DEFAULT', usage='ENCRYPT_DECRYPT', multi=False):
        out = self.observe(name, 'create-key', {'Origin': 'EXTERNAL', 'KeySpec': spec, 'KeyUsage': usage, 'MultiRegion': multi})
        return out['KeyMetadata']['KeyId'] if out else None

    def parameters(self, case, key, algorithm='RSAES_OAEP_SHA_256', spec='RSA_2048', region='us-east-1'):
        return self.observe(case, 'get-parameters-for-import', {'KeyId': key, 'WrappingAlgorithm': algorithm, 'WrappingKeySpec': spec}, region)

    def import_material(self, case, key, parameters, material, algorithm='RSAES_OAEP_SHA_256', region='us-east-1', **options):
        wrapped = wrap(parameters['PublicKey'], material, algorithm)
        params = dict(KeyId=key, EncryptedKeyMaterial=base64.b64encode(wrapped).decode(), ImportToken=parameters['ImportToken'])
        params.update(options)
        return self.observe(case, 'import-key-material', params, region)

    def wait(self, case, op, params, complete, region='us-east-1'):
        deadline = time.monotonic() + 900
        while time.monotonic() < deadline:
            out = self.observe(case, op, params, region)
            if out is not None and complete(out):
                return out
            time.sleep(3)
        raise RuntimeError('Owned KMS import transition did not complete within 15 minutes')

    def cleanup(self):
        failures = []
        for region, key in self.owned:
            out = self.observe('cleanup_' + region, 'schedule-key-deletion', {'KeyId': key, 'PendingWindowInDays': 7}, region)
            if out is None:
                out = self.observe('cleanup_status_' + region, 'describe-key', {'KeyId': key}, region)
                if not out or out['KeyMetadata']['KeyState'] not in ['PendingDeletion', 'PendingReplicaDeletion']:
                    failures.append((region, key))
            self.fixture['cleanup'].append({'region': region, 'key': out})
            self.save()
        if failures:
            raise RuntimeError('Owned keys still require cleanup: ' + str(failures))


def openssl(args, data=None):
    result = subprocess.run(['openssl', *args], input=data, capture_output=True, check=False)
    if result.returncode:
        raise RuntimeError('OpenSSL failed: ' + result.stderr.decode())
    return result.stdout


def wrap(public, material, algorithm):
    digest = 'sha1' if algorithm.endswith('SHA_1') else 'sha256'
    with tempfile.TemporaryDirectory(prefix='stackd-kms-import-') as directory:
        public_path = pathlib.Path(directory) / 'public.der'
        public_path.write_bytes(base64.b64decode(public))
        rsa_args = ['pkeyutl', '-encrypt', '-pubin', '-keyform', 'DER', '-inkey', str(public_path),
                    '-pkeyopt', 'rsa_padding_mode:oaep', '-pkeyopt', 'rsa_oaep_md:' + digest, '-pkeyopt', 'rsa_mgf1_md:' + digest]
        if algorithm.startswith('RSA_AES'):
            aes = os.urandom(32)
            return openssl(rsa_args, aes) + openssl(['enc', '-id-aes256-wrap-pad', '-K', aes.hex(), '-iv', 'A65959A6'], material)
        return openssl(rsa_args, material)


def symmetric(c):
    key = c.create('symmetric_create')
    base = {'KeyId': key}
    material = b'A' * 32
    c.observe('symmetric_empty_history', 'list-key-rotations', dict(base, IncludeKeyMaterial='ALL_KEY_MATERIAL'))
    c.observe('symmetric_delete_empty', 'delete-imported-key-material', base)
    for op in ['enable-key', 'disable-key', 'enable-key-rotation', 'disable-key-rotation', 'rotate-key-on-demand', 'get-key-rotation-status']:
        c.observe('pending_' + op, op, base)
    c.parameters('deprecated_wrapping', key, 'RSAES_PKCS1_V1_5')
    c.parameters('symmetric_hybrid_wrapping', key, 'RSA_AES_KEY_WRAP_SHA_256')
    first = c.parameters('parameters_first', key)
    second = c.parameters('parameters_second', key, 'RSAES_OAEP_SHA_1', 'RSA_3072')
    c.import_material('missing_valid_to', key, first, material)
    c.import_material('expired_valid_to', key, first, material, ValidTo=time.time() - 60)
    c.import_material('excessive_valid_to', key, first, material, ValidTo=time.time() + 367 * 86400)
    c.import_material('short_material', key, first, b'A' * 16, ExpirationModel='KEY_MATERIAL_DOES_NOT_EXPIRE')
    c.import_material('initial_import_old_token', key, first, material, ExpirationModel='KEY_MATERIAL_DOES_NOT_EXPIRE', KeyMaterialDescription='first material')
    c.observe('initial_metadata', 'describe-key', base)
    history = c.observe('initial_history', 'list-key-rotations', dict(base, IncludeKeyMaterial='ALL_KEY_MATERIAL'))
    identifier = history['Rotations'][0]['KeyMaterialId']
    c.import_material('same_token_retry', key, first, material, ExpirationModel='KEY_MATERIAL_DOES_NOT_EXPIRE')
    c.import_material('new_token_existing_material', key, second, material, 'RSAES_OAEP_SHA_1', ExpirationModel='KEY_MATERIAL_DOES_NOT_EXPIRE')
    c.import_material('no_expiry_with_valid_to', key, first, material, ExpirationModel='KEY_MATERIAL_DOES_NOT_EXPIRE', ValidTo=time.time()+3600)
    c.import_material('wrong_existing_material', key, first, b'B' * 32, ExpirationModel='KEY_MATERIAL_DOES_NOT_EXPIRE')
    c.import_material('new_same_material', key, first, material, ExpirationModel='KEY_MATERIAL_DOES_NOT_EXPIRE', ImportType='NEW_KEY_MATERIAL')
    c.import_material('existing_wrong_identifier', key, first, material, ExpirationModel='KEY_MATERIAL_DOES_NOT_EXPIRE', KeyMaterialId='0'*64)
    c.import_material('new_with_identifier', key, first, b'B'*32, ExpirationModel='KEY_MATERIAL_DOES_NOT_EXPIRE', ImportType='NEW_KEY_MATERIAL', KeyMaterialId=identifier)
    c.observe('initial_encrypt', 'encrypt', dict(base, Plaintext=base64.b64encode(b'import lifecycle').decode()))
    for op in ['enable-key-rotation', 'disable-key-rotation', 'rotate-key-on-demand', 'get-key-rotation-status']:
        c.observe('imported_' + op, op, base)
    added = c.import_material('new_second_material', key, first, b'B'*32, ExpirationModel='KEY_MATERIAL_DOES_NOT_EXPIRE', ImportType='NEW_KEY_MATERIAL', KeyMaterialDescription='pending second')
    pending = added['KeyMaterialId']
    c.observe('pending_rotation_history', 'list-key-rotations', dict(base, IncludeKeyMaterial='ALL_KEY_MATERIAL'))
    c.import_material('third_while_pending', key, first, b'C'*32, ExpirationModel='KEY_MATERIAL_DOES_NOT_EXPIRE', ImportType='NEW_KEY_MATERIAL')
    c.observe('delete_pending_rotation', 'delete-imported-key-material', dict(base, KeyMaterialId=pending))
    c.observe('after_delete_pending_metadata', 'describe-key', base)
    c.observe('after_delete_pending_history', 'list-key-rotations', dict(base, IncludeKeyMaterial='ALL_KEY_MATERIAL'))
    c.import_material('restore_second_as_new', key, first, b'B'*32, ExpirationModel='KEY_MATERIAL_DOES_NOT_EXPIRE', ImportType='NEW_KEY_MATERIAL')
    c.observe('rotate_imported', 'rotate-key-on-demand', base)
    c.wait('rotation_complete_poll', 'list-key-rotations', dict(base, IncludeKeyMaterial='ALL_KEY_MATERIAL'), lambda out: any(x['KeyMaterialId']==pending and x['KeyMaterialState']=='CURRENT' for x in out['Rotations']))
    c.observe('delete_noncurrent', 'delete-imported-key-material', dict(base, KeyMaterialId=identifier))
    c.observe('missing_noncurrent_metadata', 'describe-key', base)
    c.observe('missing_noncurrent_encrypt', 'encrypt', dict(base, Plaintext=base64.b64encode(b'missing old material').decode()))
    c.observe('missing_noncurrent_history', 'list-key-rotations', dict(base, IncludeKeyMaterial='ALL_KEY_MATERIAL'))
    c.import_material('restore_noncurrent', key, first, material, ExpirationModel='KEY_MATERIAL_DOES_NOT_EXPIRE', KeyMaterialId=identifier)
    c.observe('disable_imported', 'disable-key', base)
    c.parameters('parameters_disabled', key)
    c.import_material('reimport_disabled', key, first, b'B'*32, ExpirationModel='KEY_MATERIAL_DOES_NOT_EXPIRE')
    c.observe('after_disabled_import', 'describe-key', base)
    c.observe('enable_before_expiry', 'enable-key', base)
    c.import_material('set_short_expiry', key, first, b'B'*32, ExpirationModel='KEY_MATERIAL_EXPIRES', ValidTo=time.time()+20)
    c.wait('material_expiry_poll', 'describe-key', base, lambda out: out['KeyMetadata']['KeyState']=='PendingImport')
    c.observe('expired_history', 'list-key-rotations', dict(base, IncludeKeyMaterial='ALL_KEY_MATERIAL'))
    c.import_material('reimport_expired_current', key, first, b'B'*32, ExpirationModel='KEY_MATERIAL_DOES_NOT_EXPIRE')
    c.observe('delete_current', 'delete-imported-key-material', base)
    c.observe('delete_current_again', 'delete-imported-key-material', base)
    c.observe('delete_unknown_id', 'delete-imported-key-material', dict(base, KeyMaterialId='0'*64))
    c.observe('schedule_missing_material', 'schedule-key-deletion', dict(base, PendingWindowInDays=7))
    c.observe('cancel_missing_material', 'cancel-key-deletion', base)
    c.observe('after_cancel_missing_material', 'describe-key', base)


def main():
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--account", required=True)
    probe_args = parser.parse_args()
    c = Capture(account=probe_args.account)
    try:
        symmetric(c)
        c.fixture['capture_complete'] = True
    finally:
        c.cleanup()
        c.save()


if __name__ == '__main__':
    main()
