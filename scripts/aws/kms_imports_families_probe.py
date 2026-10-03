#!/usr/bin/env python3
"""Capture imported HMAC/asymmetric material compatibility and real crypto."""
import base64
from kms_imports_probe import Capture, openssl


def families(c):
    for spec, minimum in [('HMAC_224',28),('HMAC_256',32),('HMAC_384',48),('HMAC_512',64)]:
        key = c.create(spec+'_create',spec,'GENERATE_VERIFY_MAC')
        params = c.parameters(spec+'_parameters',key)
        for size in [minimum-1,minimum]:
            c.import_material(spec+'_length_'+str(size),key,params,b'A'*size,ExpirationModel='KEY_MATERIAL_DOES_NOT_EXPIRE')
        for field,value in [('ImportType','EXISTING_KEY_MATERIAL'),('KeyMaterialId','0'*64),('KeyMaterialDescription','hmac description')]:
            c.import_material(spec+'_'+field,key,params,b'A'*minimum,ExpirationModel='KEY_MATERIAL_DOES_NOT_EXPIRE',**{field:value})
        c.observe(spec+'_metadata','describe-key',{'KeyId':key})
        c.observe(spec+'_history','list-key-rotations',{'KeyId':key,'IncludeKeyMaterial':'ALL_KEY_MATERIAL'})
        c.observe(spec+'_mac','generate-mac',{'KeyId':key,'Message':base64.b64encode(b'imported HMAC').decode(),'MacAlgorithm':'HMAC_SHA_'+spec.split('_')[1]})
        c.observe(spec+'_delete','delete-imported-key-material',{'KeyId':key})
        c.import_material(spec+'_wrong_reimport',key,params,b'B'*minimum,ExpirationModel='KEY_MATERIAL_DOES_NOT_EXPIRE')
        c.import_material(spec+'_restore',key,params,b'A'*minimum,ExpirationModel='KEY_MATERIAL_DOES_NOT_EXPIRE')
    for spec,curve in [('RSA_2048',None),('RSA_3072',None),('RSA_4096',None),('ECC_NIST_P256','prime256v1'),('ECC_NIST_P384','secp384r1'),('ECC_NIST_P521','secp521r1'),('ECC_SECG_P256K1','secp256k1'),('ECC_NIST_EDWARDS25519','ED25519')]:
        key = c.create(spec+'_create',spec,'SIGN_VERIFY')
        if curve=='ED25519':
            pem=openssl(['genpkey','-algorithm','ED25519'])
        elif curve:
            pem=openssl(['genpkey','-algorithm','EC','-pkeyopt','ec_paramgen_curve:'+curve])
        else:
            pem=openssl(['genpkey','-algorithm','RSA','-pkeyopt','rsa_keygen_bits:'+spec.split('_')[1]])
        material=openssl(['pkcs8','-topk8','-nocrypt','-outform','DER'],pem)
        c.parameters(spec+'_direct_2048',key)
        algorithm='RSA_AES_KEY_WRAP_SHA_256' if curve is None or spec=='ECC_NIST_P521' else 'RSAES_OAEP_SHA_256'
        params=c.parameters(spec+'_parameters',key,algorithm,'RSA_3072')
        imported=c.import_material(spec+'_import',key,params,material,algorithm,ExpirationModel='KEY_MATERIAL_DOES_NOT_EXPIRE')
        if imported is None:
            continue
        c.observe(spec+'_metadata','describe-key',{'KeyId':key})
        c.observe(spec+'_history','list-key-rotations',{'KeyId':key,'IncludeKeyMaterial':'ALL_KEY_MATERIAL'})
        c.observe(spec+'_public','get-public-key',{'KeyId':key})
        # BER indefinite outer sequence is permitted by AWS's import contract.
        offset=2+(material[1]&127) if material[1]&128 else 2
        ber=b'\x30\x80'+material[offset:]+b'\x00\x00'
        c.import_material(spec+'_ber_reimport',key,params,ber,algorithm,ExpirationModel='KEY_MATERIAL_DOES_NOT_EXPIRE')
        for field,value in [('ImportType','EXISTING_KEY_MATERIAL'),('KeyMaterialDescription','asymmetric description')]:
            c.import_material(spec+'_'+field,key,params,material,algorithm,ExpirationModel='KEY_MATERIAL_DOES_NOT_EXPIRE',**{field:value})
        sign='RSASSA_PSS_SHA_256' if curve is None else ('ED25519_SHA_512' if curve=='ED25519' else 'ECDSA_SHA_256')
        if spec=='ECC_NIST_P384':sign='ECDSA_SHA_384'
        if spec=='ECC_NIST_P521':sign='ECDSA_SHA_512'
        c.observe(spec+'_sign','sign',{'KeyId':key,'Message':base64.b64encode(b'imported asymmetric signing').decode(),'SigningAlgorithm':sign})
        c.observe(spec+'_delete','delete-imported-key-material',{'KeyId':key})
        c.observe(spec+'_public_missing','get-public-key',{'KeyId':key})
        c.import_material(spec+'_restore',key,params,material,algorithm,ExpirationModel='KEY_MATERIAL_DOES_NOT_EXPIRE')
    for spec in ['ML_DSA_44','ML_DSA_65','ML_DSA_87']:
        key=c.create(spec+'_external_create',spec,'SIGN_VERIFY')
        if key:
            c.parameters(spec+'_parameters',key,'RSA_AES_KEY_WRAP_SHA_256')


def main():
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--account", required=True)
    probe_args = parser.parse_args()
    c=Capture('imports_families', account=probe_args.account)
    try:
        families(c)
        c.fixture['capture_complete']=True
    finally:
        c.cleanup()
        c.save()


if __name__=='__main__':
    main()
