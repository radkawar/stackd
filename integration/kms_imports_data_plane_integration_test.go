package stackd_test

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"

	"stackd"
)

func TestKMSImportedECDHOriginAndMaterial(t *testing.T) {
	codes := kmsNativeCodes(t, "imports_data_plane")
	c := clockCloud(t, stackd.Config{}).kms("test", "test", "")
	k := kmsExternalKey(t, c, types.KeySpecEccNistP256, types.KeyUsageTypeKeyAgreement, false)
	private, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	p := kmsImportParameters(t, c, k.KeyId, types.AlgorithmSpecRsaesOaepSha256, types.WrappingKeySpecRsa2048)
	imported := kmsImportRequest(t, k.KeyId, p, der, types.AlgorithmSpecRsaesOaepSha256)
	_, err = c.ImportKeyMaterial(t.Context(), imported)
	checkKMSNative(t, codes, "ecdh_import", err)
	peer, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	public, err := x509.MarshalPKIXPublicKey(peer.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	want, err := peer.ECDH(private.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	in := &kms.DeriveSharedSecretInput{KeyId: k.KeyId, PublicKey: public, KeyAgreementAlgorithm: types.KeyAgreementAlgorithmSpecEcdh}
	out, err := c.DeriveSharedSecret(t.Context(), in)
	checkKMSNative(t, codes, "ecdh_derive", err)
	if !bytes.Equal(out.SharedSecret, want) || out.KeyOrigin != types.OriginTypeExternal || aws.ToString(out.KeyId) != aws.ToString(k.Arn) {
		t.Fatal("ECDH lost imported material or origin", out.KeyOrigin)
	}
	in.DryRun = aws.Bool(true)
	_, err = c.DeriveSharedSecret(t.Context(), in)
	checkKMSNative(t, codes, "ecdh_dry_run", err)
	in.DryRun = nil
	_, err = c.DeleteImportedKeyMaterial(t.Context(), &kms.DeleteImportedKeyMaterialInput{KeyId: k.KeyId})
	checkKMSNative(t, codes, "ecdh_delete", err)
	_, err = c.DeriveSharedSecret(t.Context(), in)
	checkKMSNative(t, codes, "ecdh_missing_material", err)
	_, err = c.ImportKeyMaterial(t.Context(), imported)
	checkKMSNative(t, codes, "ecdh_reimport", err)
	out, err = c.DeriveSharedSecret(t.Context(), in)
	checkKMSNative(t, codes, "ecdh_derive_after_reimport", err)
	if !bytes.Equal(out.SharedSecret, want) {
		t.Fatal("reimport changed ECDH secret")
	}
}

func TestKMSImportedRSAEncryptionMaterial(t *testing.T) {
	codes := kmsNativeCodes(t, "imports_data_plane")
	c := clockCloud(t, stackd.Config{}).kms("test", "test", "")
	k := kmsExternalKey(t, c, types.KeySpecRsa2048, types.KeyUsageTypeEncryptDecrypt, false)
	private, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	p := kmsImportParameters(t, c, k.KeyId, types.AlgorithmSpecRsaAesKeyWrapSha256, types.WrappingKeySpecRsa2048)
	imported := kmsImportRequest(t, k.KeyId, p, der, types.AlgorithmSpecRsaAesKeyWrapSha256)
	_, err = c.ImportKeyMaterial(t.Context(), imported)
	checkKMSNative(t, codes, "rsa_import", err)
	message := []byte("imported RSA encryption")
	local, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, &private.PublicKey, message, nil)
	if err != nil {
		t.Fatal(err)
	}
	in := &kms.DecryptInput{KeyId: k.KeyId, CiphertextBlob: local, EncryptionAlgorithm: types.EncryptionAlgorithmSpecRsaesOaepSha256}
	decrypted, err := c.Decrypt(t.Context(), in)
	checkKMSNative(t, codes, "rsa_decrypt_openssl", err)
	if !bytes.Equal(decrypted.Plaintext, message) || decrypted.KeyMaterialId != nil {
		t.Fatal("RSA decryption did not use imported material")
	}
	encrypted, err := c.Encrypt(t.Context(), &kms.EncryptInput{KeyId: k.KeyId, Plaintext: message, EncryptionAlgorithm: types.EncryptionAlgorithmSpecRsaesOaepSha256})
	checkKMSNative(t, codes, "rsa_encrypt", err)
	plain, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, private, encrypted.CiphertextBlob, nil)
	if err != nil || !bytes.Equal(plain, message) {
		t.Fatal("RSA ciphertext is not interoperable", err)
	}
	_, err = c.DeleteImportedKeyMaterial(t.Context(), &kms.DeleteImportedKeyMaterialInput{KeyId: k.KeyId})
	checkKMSNative(t, codes, "rsa_delete", err)
	_, err = c.Decrypt(t.Context(), in)
	checkKMSNative(t, codes, "rsa_missing_material", err)
	_, err = c.ImportKeyMaterial(t.Context(), imported)
	checkKMSNative(t, codes, "rsa_reimport", err)
	decrypted, err = c.Decrypt(t.Context(), in)
	checkKMSNative(t, codes, "rsa_decrypt_after_reimport", err)
	if !bytes.Equal(decrypted.Plaintext, message) {
		t.Fatal("reimport lost RSA ciphertext")
	}
}
