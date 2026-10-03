#!/usr/bin/env python3
"""Capture replica material loss after a primary rotation is accepted."""
import datetime
from kms_imports_probe import Capture


def main():
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--account", required=True)
    probe_args = parser.parse_args()
    c = Capture('imports_rotation_replica', account=probe_args.account)
    try:
        key = c.create('create_primary', multi=True)
        east = c.parameters('primary_parameters', key)
        c.import_material('primary_first_import', key, east, b'A' * 32, ExpirationModel='KEY_MATERIAL_DOES_NOT_EXPIRE')
        c.observe('replicate', 'replicate-key', {'KeyId': key, 'ReplicaRegion': 'us-west-2'})
        c.wait('replica_ready_poll', 'describe-key', {'KeyId': key}, lambda out: out['KeyMetadata']['KeyState'] == 'PendingImport', region='us-west-2')
        west = c.parameters('replica_parameters', key, region='us-west-2')
        c.import_material('replica_first_import', key, west, b'A' * 32, region='us-west-2', ExpirationModel='KEY_MATERIAL_DOES_NOT_EXPIRE')
        second = c.import_material('primary_second_import', key, east, b'B' * 32, ImportType='NEW_KEY_MATERIAL', ExpirationModel='KEY_MATERIAL_DOES_NOT_EXPIRE')
        c.import_material('replica_second_import', key, west, b'B' * 32, region='us-west-2', ExpirationModel='KEY_MATERIAL_DOES_NOT_EXPIRE')
        c.observe('rotate_primary', 'rotate-key-on-demand', {'KeyId': key})
        c.observe('delete_replica_pending', 'delete-imported-key-material', {'KeyId': key, 'KeyMaterialId': second['KeyMaterialId']}, region='us-west-2')
        c.observe('status_after_replica_delete', 'get-key-rotation-status', {'KeyId': key})
        c.wait('rotation_status_poll', 'get-key-rotation-status', {'KeyId': key}, lambda out: 'OnDemandRotationStartDate' not in out)
        for region in ['us-east-1', 'us-west-2']:
            c.observe('after_rotation_metadata_' + region, 'describe-key', {'KeyId': key}, region=region)
            c.observe('after_rotation_history_' + region, 'list-key-rotations', {'KeyId': key, 'IncludeKeyMaterial': 'ALL_KEY_MATERIAL'}, region=region)
            c.observe('encrypt_after_rotation_' + region, 'encrypt', {'KeyId': key, 'Plaintext': 'cmVnaW9uYWwgcm90YXRpb24='}, region=region)
        c.import_material('replica_restore', key, west, b'B' * 32, region='us-west-2', ExpirationModel='KEY_MATERIAL_DOES_NOT_EXPIRE')
        c.observe('replica_restored_metadata', 'describe-key', {'KeyId': key}, region='us-west-2')
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
