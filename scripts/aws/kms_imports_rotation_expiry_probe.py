#!/usr/bin/env python3
"""Capture activation of expired pending material and deletion during rotation."""
import datetime
import time
from kms_imports_probe import Capture


def main():
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--account", required=True)
    probe_args = parser.parse_args()
    c = Capture('imports_rotation_expiry', account=probe_args.account)
    try:
        key = c.create('create_external')
        p = c.parameters('parameters', key)
        c.import_material('first_import', key, p, b'A' * 32, ExpirationModel='KEY_MATERIAL_DOES_NOT_EXPIRE')
        first_ciphertext = c.observe('encrypt_initial', 'encrypt', {'KeyId': key, 'Plaintext': 'b2xkIG1hdGVyaWFs'})
        c.import_material('expiring_pending', key, p, b'B' * 32, ImportType='NEW_KEY_MATERIAL', ValidTo=int(time.time()) + 15)
        time.sleep(20)
        c.observe('expired_pending_metadata', 'describe-key', {'KeyId': key})
        c.observe('expired_pending_history', 'list-key-rotations', {'KeyId': key, 'IncludeKeyMaterial': 'ALL_KEY_MATERIAL'})
        c.observe('encrypt_with_expired_pending', 'encrypt', {'KeyId': key, 'Plaintext': 'cGVuZGluZyBleHBpcnk='})
        rotated = c.observe('rotate_expired_pending', 'rotate-key-on-demand', {'KeyId': key})
        if rotated is not None:
            c.wait('expired_rotation_status_poll', 'get-key-rotation-status', {'KeyId': key}, lambda out: 'OnDemandRotationStartDate' not in out)
        c.observe('after_expired_rotation_metadata', 'describe-key', {'KeyId': key})
        c.observe('after_expired_rotation_history', 'list-key-rotations', {'KeyId': key, 'IncludeKeyMaterial': 'ALL_KEY_MATERIAL'})
        c.observe('encrypt_after_expired_rotation', 'encrypt', {'KeyId': key, 'Plaintext': 'YWZ0ZXIgcm90YXRpb24='})
        c.observe('decrypt_initial_after_expired_rotation', 'decrypt', {'CiphertextBlob': first_ciphertext['CiphertextBlob']})
        c.import_material('restore_expired_pending', key, p, b'B' * 32, ExpirationModel='KEY_MATERIAL_DOES_NOT_EXPIRE')
        c.observe('after_restore_metadata', 'describe-key', {'KeyId': key})
        c.observe('after_restore_history', 'list-key-rotations', {'KeyId': key, 'IncludeKeyMaterial': 'ALL_KEY_MATERIAL'})
        c.observe('decrypt_initial_after_restore', 'decrypt', {'CiphertextBlob': first_ciphertext['CiphertextBlob']})
        third = c.import_material('third_import', key, p, b'C' * 32, ImportType='NEW_KEY_MATERIAL', ExpirationModel='KEY_MATERIAL_DOES_NOT_EXPIRE')
        c.observe('rotate_third', 'rotate-key-on-demand', {'KeyId': key})
        if third is not None:
            c.observe('delete_pending_during_rotation', 'delete-imported-key-material', {'KeyId': key, 'KeyMaterialId': third['KeyMaterialId']})
            c.wait('deleted_rotation_status_poll', 'get-key-rotation-status', {'KeyId': key}, lambda out: 'OnDemandRotationStartDate' not in out)
            c.observe('after_pending_delete_metadata', 'describe-key', {'KeyId': key})
            c.observe('after_pending_delete_history', 'list-key-rotations', {'KeyId': key, 'IncludeKeyMaterial': 'ALL_KEY_MATERIAL'})
        c.fixture['capture_complete'] = True
    except RuntimeError as error:
        c.fixture['incomplete_reason'] = str(error)
        raise
    finally:
        c.fixture['last_checked_at'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        c.cleanup()
        c.save()


if __name__ == '__main__':
    main()
