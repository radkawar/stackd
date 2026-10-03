#!/usr/bin/env python3
"""Capture import binding, expiry and accepted-rotation mutation boundaries."""
import base64
import time
from kms_imports_probe import Capture, wrap


def main():
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--account", required=True)
    probe_args = parser.parse_args()
    c = Capture('imports_edges', account=probe_args.account)
    try:
        key = c.create('create_external')
        other = c.create('create_other_external')
        generated = c.observe('create_generated', 'create-key')['KeyMetadata']['KeyId']
        c.parameters('parameters_generated', generated)
        p = c.parameters('parameters', key)
        other_p = c.parameters('other_parameters', other)
        wrapped = wrap(p['PublicKey'], b'A' * 32, 'RSAES_OAEP_SHA_256')
        request = dict(KeyId=key, EncryptedKeyMaterial=base64.b64encode(wrapped).decode(), ImportToken=p['ImportToken'], ExpirationModel='KEY_MATERIAL_DOES_NOT_EXPIRE')
        c.observe('token_other_key', 'import-key-material', dict(request, ImportToken=other_p['ImportToken']))
        c.observe('token_corrupt', 'import-key-material', dict(request, ImportToken=base64.b64encode(b'x' * 32).decode()))
        c.observe('ciphertext_corrupt', 'import-key-material', dict(request, EncryptedKeyMaterial=base64.b64encode(b'x' * 256).decode()))
        c.import_material('first_import', key, p, b'A' * 32, ExpirationModel='KEY_MATERIAL_DOES_NOT_EXPIRE')
        pending = c.import_material('expiring_pending', key, p, b'B' * 32, ImportType='NEW_KEY_MATERIAL', ValidTo=int(time.time()) + 10)
        time.sleep(15)
        c.observe('pending_expired_metadata', 'describe-key', {'KeyId': key})
        c.observe('pending_expired_history', 'list-key-rotations', {'KeyId': key, 'IncludeKeyMaterial': 'ALL_KEY_MATERIAL'})
        c.import_material('pending_after_expiry_new', key, p, b'B' * 32, ImportType='NEW_KEY_MATERIAL', ExpirationModel='KEY_MATERIAL_DOES_NOT_EXPIRE')
        history = c.observe('pending_before_rotation', 'list-key-rotations', {'KeyId': key, 'IncludeKeyMaterial': 'ALL_KEY_MATERIAL'})
        if any(row.get('ImportState') == 'PENDING_IMPORT' for row in history['Rotations']):
            c.import_material('restore_pending_after_expiry', key, p, b'B' * 32, ExpirationModel='KEY_MATERIAL_DOES_NOT_EXPIRE')
        c.observe('rotate', 'rotate-key-on-demand', {'KeyId': key})
        c.observe('delete_pending_during_rotation', 'delete-imported-key-material', {'KeyId': key, 'KeyMaterialId': pending['KeyMaterialId']})
        c.import_material('reimport_during_rotation', key, p, b'A' * 32, ExpirationModel='KEY_MATERIAL_DOES_NOT_EXPIRE')
        c.observe('rotation_status_after_mutations', 'get-key-rotation-status', {'KeyId': key})
        c.observe('history_default', 'list-key-rotations', {'KeyId': key})
        c.fixture['capture_complete'] = True
    finally:
        c.cleanup()
        c.save()


if __name__ == '__main__':
    main()
