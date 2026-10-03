#!/usr/bin/env python3
"""Observe the final state of expired material pending rotation."""
import datetime
import time
from kms_imports_probe import Capture


def main():
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--account", required=True)
    probe_args = parser.parse_args()
    c = Capture('imports_expiry', account=probe_args.account)
    try:
        key = c.create('create_external')
        p = c.parameters('parameters', key)
        c.import_material('first_import', key, p, b'A' * 32, ExpirationModel='KEY_MATERIAL_DOES_NOT_EXPIRE')
        pending = c.import_material('expiring_pending', key, p, b'B' * 32, ImportType='NEW_KEY_MATERIAL', ValidTo=int(time.time()) + 10)
        c.wait('expiry_history_poll', 'list-key-rotations', {'KeyId': key, 'IncludeKeyMaterial': 'ALL_KEY_MATERIAL'}, lambda out: not any(row.get('KeyMaterialId') == pending['KeyMaterialId'] and row.get('ImportState') == 'IMPORTED' for row in out['Rotations']))
        c.observe('after_expiry_metadata', 'describe-key', {'KeyId': key})
        c.import_material('pending_new_after_expiry', key, p, b'B' * 32, ImportType='NEW_KEY_MATERIAL', ExpirationModel='KEY_MATERIAL_DOES_NOT_EXPIRE')
        c.import_material('pending_existing_after_expiry', key, p, b'B' * 32, ExpirationModel='KEY_MATERIAL_DOES_NOT_EXPIRE')
        c.observe('rotate', 'rotate-key-on-demand', {'KeyId': key})
        c.observe('delete_pending_during_rotation', 'delete-imported-key-material', {'KeyId': key, 'KeyMaterialId': pending['KeyMaterialId']})
        c.wait('rotation_status_poll', 'get-key-rotation-status', {'KeyId': key}, lambda out: 'OnDemandRotationStartDate' not in out)
        c.observe('after_rotation_delete_history', 'list-key-rotations', {'KeyId': key, 'IncludeKeyMaterial': 'ALL_KEY_MATERIAL'})
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
