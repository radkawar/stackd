#!/usr/bin/env python3
"""Capture independent regional imports and coordinated imported-key rotation."""
import time
from kms_imports_probe import Capture


def multi_region(c):
    west='us-west-2'
    key=c.create('multi_create',multi=True)
    base={'KeyId':key}
    replica=c.observe('replicate_pending_import','replicate-key',dict(base,ReplicaRegion=west))
    primary=c.parameters('primary_parameters',key)
    if replica:
        c.wait('replica_pending_poll','describe-key',base,lambda out:out['KeyMetadata']['KeyState']=='PendingImport',west)
        early=c.parameters('early_replica_parameters',key,region=west)
        c.import_material('replica_before_primary',key,early,b'A'*32,region=west,ExpirationModel='KEY_MATERIAL_DOES_NOT_EXPIRE')
    first=c.import_material('primary_first_import',key,primary,b'A'*32,ExpirationModel='KEY_MATERIAL_DOES_NOT_EXPIRE',KeyMaterialDescription='primary first')
    if not replica:
        replica=c.observe('replicate_imported_primary','replicate-key',dict(base,ReplicaRegion=west))
        c.wait('replica_pending_poll','describe-key',base,lambda out:out['KeyMetadata']['KeyState']=='PendingImport',west)
    c.observe('replica_missing_first_history','list-key-rotations',dict(base,IncludeKeyMaterial='ALL_KEY_MATERIAL'),west)
    params=c.parameters('replica_parameters',key,region=west)
    c.import_material('replica_wrong_first',key,params,b'B'*32,region=west,ExpirationModel='KEY_MATERIAL_DOES_NOT_EXPIRE')
    c.import_material('replica_first_import',key,params,b'A'*32,region=west,ExpirationModel='KEY_MATERIAL_DOES_NOT_EXPIRE',KeyMaterialDescription='replica first')
    c.observe('replica_first_history','list-key-rotations',dict(base,IncludeKeyMaterial='ALL_KEY_MATERIAL'),west)
    second=c.import_material('primary_stage_second',key,primary,b'B'*32,ExpirationModel='KEY_MATERIAL_DOES_NOT_EXPIRE',ImportType='NEW_KEY_MATERIAL')
    c.observe('primary_missing_replica_history','list-key-rotations',dict(base,IncludeKeyMaterial='ALL_KEY_MATERIAL'))
    c.observe('replica_missing_second_history','list-key-rotations',dict(base,IncludeKeyMaterial='ALL_KEY_MATERIAL'),west)
    c.observe('rotate_before_replica_import','rotate-key-on-demand',base)
    c.import_material('replica_new_type_rejected',key,params,b'B'*32,region=west,ExpirationModel='KEY_MATERIAL_DOES_NOT_EXPIRE',ImportType='NEW_KEY_MATERIAL')
    c.import_material('replica_second_import',key,params,b'B'*32,region=west,ExpirationModel='KEY_MATERIAL_EXPIRES',ValidTo=time.time()+3600,KeyMaterialDescription='replica second')
    c.observe('primary_ready_history','list-key-rotations',dict(base,IncludeKeyMaterial='ALL_KEY_MATERIAL'))
    c.observe('replica_ready_history','list-key-rotations',dict(base,IncludeKeyMaterial='ALL_KEY_MATERIAL'),west)
    c.observe('delete_replica_pending','delete-imported-key-material',dict(base,KeyMaterialId=second['KeyMaterialId']),west)
    c.observe('primary_after_replica_pending_delete','list-key-rotations',dict(base,IncludeKeyMaterial='ALL_KEY_MATERIAL'))
    c.import_material('replica_restore_pending',key,params,b'B'*32,region=west,ExpirationModel='KEY_MATERIAL_DOES_NOT_EXPIRE')
    c.observe('delete_primary_pending','delete-imported-key-material',dict(base,KeyMaterialId=second['KeyMaterialId']))
    c.observe('replica_after_primary_pending_delete','list-key-rotations',dict(base,IncludeKeyMaterial='ALL_KEY_MATERIAL'),west)
    c.import_material('primary_restage_second',key,primary,b'B'*32,ExpirationModel='KEY_MATERIAL_DOES_NOT_EXPIRE',ImportType='NEW_KEY_MATERIAL')
    c.import_material('replica_restage_second',key,params,b'B'*32,region=west,ExpirationModel='KEY_MATERIAL_DOES_NOT_EXPIRE')
    c.observe('rotate_imported_multi','rotate-key-on-demand',base)
    c.wait('multi_rotation_poll','list-key-rotations',dict(base,IncludeKeyMaterial='ALL_KEY_MATERIAL'),lambda out:any(x['KeyMaterialId']==second['KeyMaterialId'] and x['KeyMaterialState']=='CURRENT' for x in out['Rotations']))
    c.observe('rotated_replica_history','list-key-rotations',dict(base,IncludeKeyMaterial='ALL_KEY_MATERIAL'),west)
    c.observe('delete_replica_noncurrent','delete-imported-key-material',dict(base,KeyMaterialId=first['KeyMaterialId']),west)
    c.observe('primary_after_replica_loss','describe-key',base)
    c.observe('replica_after_replica_loss','describe-key',base,west)
    c.import_material('restore_replica_noncurrent',key,params,b'A'*32,region=west,ExpirationModel='KEY_MATERIAL_DOES_NOT_EXPIRE')
    c.import_material('primary_set_expiry',key,primary,b'B'*32,ExpirationModel='KEY_MATERIAL_EXPIRES',ValidTo=time.time()+20)
    c.wait('primary_expiry_poll','describe-key',base,lambda out:out['KeyMetadata']['KeyState']=='PendingImport')
    c.observe('replica_after_primary_expiry','describe-key',base,west)


def main():
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--account", required=True)
    probe_args = parser.parse_args()
    c=Capture('imports_multi_region', account=probe_args.account)
    try:
        multi_region(c)
        c.fixture['capture_complete']=True
    finally:
        c.cleanup()
        c.save()


if __name__=='__main__':
    main()
