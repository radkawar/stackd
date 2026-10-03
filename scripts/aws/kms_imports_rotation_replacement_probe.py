#!/usr/bin/env python3
"""Capture whether accepted rotations can consume replacement pending material."""
import datetime
from kms_imports_probe import Capture


def main():
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--account", required=True)
    probe_args = parser.parse_args()
    c = Capture('imports_rotation_replacement', account=probe_args.account)
    try:
        key = c.create('create_external')
        p = c.parameters('parameters', key)
        c.import_material('first_import', key, p, b'A' * 32, ExpirationModel='KEY_MATERIAL_DOES_NOT_EXPIRE')
        pending = c.import_material('second_import', key, p, b'B' * 32, ImportType='NEW_KEY_MATERIAL', ExpirationModel='KEY_MATERIAL_DOES_NOT_EXPIRE')
        c.observe('rotate_second', 'rotate-key-on-demand', {'KeyId': key})
        c.observe('status_second_started', 'get-key-rotation-status', {'KeyId': key})
        c.observe('delete_second', 'delete-imported-key-material', {'KeyId': key, 'KeyMaterialId': pending['KeyMaterialId']})
        c.observe('status_after_delete_second', 'get-key-rotation-status', {'KeyId': key})
        c.import_material('third_import_without_rotate', key, p, b'C' * 32, ImportType='NEW_KEY_MATERIAL', ExpirationModel='KEY_MATERIAL_DOES_NOT_EXPIRE')
        c.observe('status_after_third_import', 'get-key-rotation-status', {'KeyId': key})
        c.wait('first_request_status_poll', 'get-key-rotation-status', {'KeyId': key}, lambda out: 'OnDemandRotationStartDate' not in out)
        c.observe('after_first_request_metadata', 'describe-key', {'KeyId': key})
        c.observe('after_first_request_history', 'list-key-rotations', {'KeyId': key, 'IncludeKeyMaterial': 'ALL_KEY_MATERIAL'})
        c.observe('rotate_third', 'rotate-key-on-demand', {'KeyId': key})
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
