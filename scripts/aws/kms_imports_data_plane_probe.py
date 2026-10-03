#!/usr/bin/env python3
"""Cross-check imported RSA encryption and ECDH with OpenSSL."""
import base64
import pathlib
import tempfile
from kms_imports_probe import Capture, openssl, wrap


def main():
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--account", required=True)
    probe_args = parser.parse_args()
    c = Capture('imports_data_plane', account=probe_args.account)
    try:
        key = c.create('ecdh_create', 'ECC_NIST_P256', 'KEY_AGREEMENT')
        private = openssl(['genpkey', '-algorithm', 'EC', '-pkeyopt', 'ec_paramgen_curve:prime256v1'])
        material = openssl(['pkcs8', '-topk8', '-nocrypt', '-outform', 'DER'], private)
        parameters = c.parameters('ecdh_parameters', key)
        c.import_material('ecdh_import', key, parameters, material, ExpirationModel='KEY_MATERIAL_DOES_NOT_EXPIRE')
        peer = openssl(['genpkey', '-algorithm', 'EC', '-pkeyopt', 'ec_paramgen_curve:prime256v1'])
        peer_public = openssl(['pkey', '-pubout', '-outform', 'DER'], peer)
        request = {'KeyId': key, 'PublicKey': base64.b64encode(peer_public).decode(), 'KeyAgreementAlgorithm': 'ECDH'}
        out = c.observe('ecdh_derive', 'derive-shared-secret', request)
        with tempfile.TemporaryDirectory(prefix='stackd-kms-import-ecdh-') as directory:
            private_path = pathlib.Path(directory) / 'private.pem'
            peer_path = pathlib.Path(directory) / 'peer.der'
            private_path.write_bytes(private)
            private_path.chmod(0o600)
            peer_path.write_bytes(peer_public)
            expected = openssl(['pkeyutl', '-derive', '-inkey', str(private_path), '-peerkey', str(peer_path), '-peerform', 'DER'])
        if out is None or base64.b64decode(out['SharedSecret']) != expected:
            raise RuntimeError('Native ECDH result differs from OpenSSL')
        c.fixture['ecdh_openssl_matches'] = True
        c.observe('ecdh_dry_run', 'derive-shared-secret', dict(request, DryRun=True))
        c.observe('ecdh_delete', 'delete-imported-key-material', {'KeyId': key})
        c.observe('ecdh_missing_material', 'derive-shared-secret', request)
        c.import_material('ecdh_reimport', key, parameters, material, ExpirationModel='KEY_MATERIAL_DOES_NOT_EXPIRE')
        c.observe('ecdh_derive_after_reimport', 'derive-shared-secret', request)
        key = c.create('rsa_create', 'RSA_2048', 'ENCRYPT_DECRYPT')
        private = openssl(['genpkey', '-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:2048'])
        material = openssl(['pkcs8', '-topk8', '-nocrypt', '-outform', 'DER'], private)
        parameters = c.parameters('rsa_parameters', key, 'RSA_AES_KEY_WRAP_SHA_256')
        c.import_material('rsa_import', key, parameters, material, 'RSA_AES_KEY_WRAP_SHA_256', ExpirationModel='KEY_MATERIAL_DOES_NOT_EXPIRE')
        public = c.observe('rsa_public', 'get-public-key', {'KeyId': key})
        message = b'imported RSA encryption'
        encrypted = wrap(public['PublicKey'], message, 'RSAES_OAEP_SHA_256')
        request = {'KeyId': key, 'CiphertextBlob': base64.b64encode(encrypted).decode(), 'EncryptionAlgorithm': 'RSAES_OAEP_SHA_256'}
        out = c.observe('rsa_decrypt_openssl', 'decrypt', request)
        if out is None or base64.b64decode(out['Plaintext']) != message:
            raise RuntimeError('Native RSA plaintext differs from OpenSSL input')
        c.fixture['rsa_openssl_matches'] = True
        c.observe('rsa_encrypt', 'encrypt', {'KeyId': key, 'Plaintext': base64.b64encode(message).decode(), 'EncryptionAlgorithm': 'RSAES_OAEP_SHA_256'})
        c.observe('rsa_delete', 'delete-imported-key-material', {'KeyId': key})
        c.observe('rsa_missing_material', 'decrypt', request)
        c.import_material('rsa_reimport', key, parameters, material, 'RSA_AES_KEY_WRAP_SHA_256', ExpirationModel='KEY_MATERIAL_DOES_NOT_EXPIRE')
        c.observe('rsa_decrypt_after_reimport', 'decrypt', request)
        c.fixture['capture_complete'] = True
    finally:
        c.cleanup()
        c.save()


if __name__ == '__main__':
    main()
