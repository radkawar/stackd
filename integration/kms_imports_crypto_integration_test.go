package stackd_test

import (
	"bytes"
	"crypto"
	"crypto/hmac"
	"encoding/asn1"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"

	"stackd"
)

func TestKMSImportedHMACNativeAndActualBytes(t *testing.T) {
	codes := kmsNativeCodes(t, "imports_families")
	c := clockCloud(t, stackd.Config{}).kms("test", "test", "")
	for _, tc := range []struct {
		spec      types.KeySpec
		algorithm types.MacAlgorithmSpec
		hash      crypto.Hash
	}{
		{types.KeySpecHmac224, types.MacAlgorithmSpecHmacSha224, crypto.SHA224},
		{types.KeySpecHmac256, types.MacAlgorithmSpecHmacSha256, crypto.SHA256},
		{types.KeySpecHmac384, types.MacAlgorithmSpecHmacSha384, crypto.SHA384},
		{types.KeySpecHmac512, types.MacAlgorithmSpecHmacSha512, crypto.SHA512},
	} {
		t.Run(string(tc.spec), func(t *testing.T) {
			k := kmsExternalKey(t, c, tc.spec, types.KeyUsageTypeGenerateVerifyMac, false)
			p := kmsImportParameters(t, c, k.KeyId, types.AlgorithmSpecRsaesOaepSha1, types.WrappingKeySpecRsa2048)
			bad := kmsImportRequest(t, k.KeyId, p, bytes.Repeat([]byte{0xaa}, tc.hash.Size()-1), types.AlgorithmSpecRsaesOaepSha1)
			_, err := c.ImportKeyMaterial(t.Context(), bad)
			assertAPIError(t, err, "InvalidCiphertextException")
			material := bytes.Repeat([]byte{0xaa}, tc.hash.Size())
			in := kmsImportRequest(t, k.KeyId, p, material, types.AlgorithmSpecRsaesOaepSha1)
			out, err := c.ImportKeyMaterial(t.Context(), in)
			if err != nil || out.KeyMaterialId != nil {
				t.Fatal("HMAC import fields", out, err)
			}
			in.ImportType = types.ImportTypeExistingKeyMaterial
			_, err = c.ImportKeyMaterial(t.Context(), in)
			checkKMSNative(t, codes, string(tc.spec)+"_ImportType", err)
			in.ImportType = ""
			_, err = c.ListKeyRotations(t.Context(), &kms.ListKeyRotationsInput{KeyId: k.KeyId, IncludeKeyMaterial: types.IncludeKeyMaterialAllKeyMaterial})
			checkKMSNative(t, codes, string(tc.spec)+"_history", err)
			m := kmsImportMetadata(t, c, k.KeyId, types.KeyStateEnabled)
			if m.CurrentKeyMaterialId != nil || m.ExpirationModel != types.ExpirationModelTypeKeyMaterialDoesNotExpire {
				t.Fatal("HMAC metadata", m)
			}
			message := []byte("imported HMAC material")
			mac, err := c.GenerateMac(t.Context(), &kms.GenerateMacInput{KeyId: k.KeyId, Message: message, MacAlgorithm: tc.algorithm})
			checkKMSNative(t, codes, string(tc.spec)+"_mac", err)
			want := hmac.New(tc.hash.New, material)
			want.Write(message)
			if !hmac.Equal(mac.Mac, want.Sum(nil)) {
				t.Fatal("KMS did not use imported HMAC bytes")
			}
			deleted, err := c.DeleteImportedKeyMaterial(t.Context(), &kms.DeleteImportedKeyMaterialInput{KeyId: k.KeyId})
			checkKMSNative(t, codes, string(tc.spec)+"_delete", err)
			if deleted.KeyMaterialId != nil {
				t.Fatal("HMAC deletion exposed a material ID")
			}
			wrong := kmsImportRequest(t, k.KeyId, p, bytes.Repeat([]byte{0xbb}, tc.hash.Size()), types.AlgorithmSpecRsaesOaepSha1)
			_, err = c.ImportKeyMaterial(t.Context(), wrong)
			checkKMSNative(t, codes, string(tc.spec)+"_wrong_reimport", err)
			_, err = c.ImportKeyMaterial(t.Context(), in)
			checkKMSNative(t, codes, string(tc.spec)+"_restore", err)
		})
	}
	// AWS permits HMAC material up to 1024 bits, independently of MAC size.
	for _, size := range []int{128, 129} {
		k := kmsExternalKey(t, c, types.KeySpecHmac256, types.KeyUsageTypeGenerateVerifyMac, false)
		p := kmsImportParameters(t, c, k.KeyId, types.AlgorithmSpecRsaesOaepSha256, types.WrappingKeySpecRsa2048)
		_, err := c.ImportKeyMaterial(t.Context(), kmsImportRequest(t, k.KeyId, p, bytes.Repeat([]byte{1}, size), types.AlgorithmSpecRsaesOaepSha256))
		if size == 128 {
			if err != nil {
				t.Fatal(err)
			}
		} else {
			assertAPIError(t, err, "InvalidCiphertextException")
		}
	}
}

func TestKMSImportedAsymmetricNativeAndOpenSSL(t *testing.T) {
	codes := kmsNativeCodes(t, "imports_families")
	c := clockCloud(t, stackd.Config{}).kms("test", "test", "")
	for _, tc := range []struct {
		spec     types.KeySpec
		generate []string
		wrapping types.AlgorithmSpec
	}{
		{types.KeySpecRsa2048, []string{"-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048"}, types.AlgorithmSpecRsaAesKeyWrapSha256},
		{types.KeySpecRsa3072, []string{"-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:3072"}, types.AlgorithmSpecRsaAesKeyWrapSha1},
		{types.KeySpecRsa4096, []string{"-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:4096"}, types.AlgorithmSpecRsaAesKeyWrapSha256},
		{types.KeySpecEccNistP256, []string{"-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256"}, types.AlgorithmSpecRsaesOaepSha256},
		{types.KeySpecEccNistP384, []string{"-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-384"}, types.AlgorithmSpecRsaAesKeyWrapSha1},
		{types.KeySpecEccNistP521, []string{"-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-521"}, types.AlgorithmSpecRsaAesKeyWrapSha256},
		{types.KeySpecEccSecgP256k1, []string{"-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:secp256k1"}, types.AlgorithmSpecRsaesOaepSha256},
		{types.KeySpecEccNistEdwards25519, []string{"-algorithm", "ED25519"}, types.AlgorithmSpecRsaesOaepSha256},
	} {
		t.Run(string(tc.spec), func(t *testing.T) {
			pem := importOpenSSL(t, nil, append([]string{"genpkey"}, tc.generate...)...)
			der := importOpenSSL(t, pem, "pkcs8", "-topk8", "-nocrypt", "-outform", "DER")
			public := importOpenSSL(t, pem, "pkey", "-pubout", "-outform", "DER")
			k := kmsExternalKey(t, c, tc.spec, types.KeyUsageTypeSignVerify, false)
			_, err := c.GetParametersForImport(t.Context(), &kms.GetParametersForImportInput{KeyId: k.KeyId, WrappingAlgorithm: types.AlgorithmSpecRsaesOaepSha256, WrappingKeySpec: types.WrappingKeySpecRsa2048})
			checkKMSNative(t, codes, string(tc.spec)+"_direct_2048", err)
			wrappingSpec := types.WrappingKeySpecRsa2048
			if tc.spec == types.KeySpecEccNistEdwards25519 {
				wrappingSpec = types.WrappingKeySpecRsa3072
			}
			p := kmsImportParameters(t, c, k.KeyId, tc.wrapping, wrappingSpec)
			in := kmsImportRequest(t, k.KeyId, p, der, tc.wrapping)
			out, err := c.ImportKeyMaterial(t.Context(), in)
			checkKMSNative(t, codes, string(tc.spec)+"_import", err)
			if out.KeyMaterialId != nil {
				t.Fatal("asymmetric import exposed material ID")
			}
			got, err := c.GetPublicKey(t.Context(), &kms.GetPublicKeyInput{KeyId: k.KeyId})
			checkKMSNative(t, codes, string(tc.spec)+"_public", err)
			if !bytes.Equal(got.PublicKey, public) {
				t.Fatal("imported public key differs from OpenSSL")
			}
			var outer asn1.RawValue
			if _, err := asn1.Unmarshal(der, &outer); err != nil {
				t.Fatal(err)
			}
			ber := append(append([]byte{0x30, 0x80}, outer.Bytes...), 0, 0)
			_, err = c.ImportKeyMaterial(t.Context(), kmsImportRequest(t, k.KeyId, p, ber, tc.wrapping))
			checkKMSNative(t, codes, string(tc.spec)+"_ber_reimport", err)
			message := []byte("OpenSSL validates imported private material")
			algorithm := got.SigningAlgorithms[0]
			if tc.spec == types.KeySpecEccNistEdwards25519 {
				algorithm = types.SigningAlgorithmSpecEd25519Sha512
			}
			signed, err := c.Sign(t.Context(), &kms.SignInput{KeyId: k.KeyId, Message: message, SigningAlgorithm: algorithm})
			checkKMSNative(t, codes, string(tc.spec)+"_sign", err)
			dir := t.TempDir()
			for name, data := range map[string][]byte{"public.der": public, "message": message, "signature": signed.Signature} {
				if err := os.WriteFile(filepath.Join(dir, name), data, 0600); err != nil {
					t.Fatal(err)
				}
			}
			args := []string{"pkeyutl", "-verify", "-pubin", "-keyform", "DER", "-inkey", filepath.Join(dir, "public.der"), "-rawin", "-in", filepath.Join(dir, "message"), "-sigfile", filepath.Join(dir, "signature")}
			switch algorithm {
			case types.SigningAlgorithmSpecRsassaPssSha256:
				args = append(args, "-digest", "sha256", "-pkeyopt", "rsa_padding_mode:pss", "-pkeyopt", "rsa_pss_saltlen:digest")
			case types.SigningAlgorithmSpecRsassaPkcs1V15Sha256, types.SigningAlgorithmSpecEcdsaSha256:
				args = append(args, "-digest", "sha256")
			case types.SigningAlgorithmSpecEcdsaSha384:
				args = append(args, "-digest", "sha384")
			case types.SigningAlgorithmSpecEcdsaSha512:
				args = append(args, "-digest", "sha512")
			}
			importOpenSSL(t, nil, args...)
			_, err = c.DeleteImportedKeyMaterial(t.Context(), &kms.DeleteImportedKeyMaterialInput{KeyId: k.KeyId})
			checkKMSNative(t, codes, string(tc.spec)+"_delete", err)
			_, err = c.GetPublicKey(t.Context(), &kms.GetPublicKeyInput{KeyId: k.KeyId})
			checkKMSNative(t, codes, string(tc.spec)+"_public_missing", err)
			_, err = c.ImportKeyMaterial(t.Context(), in)
			checkKMSNative(t, codes, string(tc.spec)+"_restore", err)
		})
	}
}

func TestKMSImportWrappedMaterialIntegrity(t *testing.T) {
	c := clockCloud(t, stackd.Config{}).kms("test", "test", "")
	k := kmsExternalKey(t, c, types.KeySpecRsa2048, types.KeyUsageTypeSignVerify, false)
	p := kmsImportParameters(t, c, k.KeyId, types.AlgorithmSpecRsaAesKeyWrapSha256, types.WrappingKeySpecRsa2048)
	pem := importOpenSSL(t, nil, "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048")
	der := importOpenSSL(t, pem, "pkcs8", "-topk8", "-nocrypt", "-outform", "DER")
	in := kmsImportRequest(t, k.KeyId, p, der, types.AlgorithmSpecRsaAesKeyWrapSha256)
	for _, pos := range []int{0, 255, 256, len(in.EncryptedKeyMaterial) - 1} {
		bad := *in
		bad.EncryptedKeyMaterial = bytes.Clone(in.EncryptedKeyMaterial)
		bad.EncryptedKeyMaterial[pos] ^= 1
		_, err := c.ImportKeyMaterial(t.Context(), &bad)
		assertAPIError(t, err, "InvalidCiphertextException")
	}
	for _, size := range []int{1, 256, 264, len(in.EncryptedKeyMaterial) - 1} {
		bad := *in
		bad.EncryptedKeyMaterial = in.EncryptedKeyMaterial[:size]
		_, err := c.ImportKeyMaterial(t.Context(), &bad)
		assertAPIError(t, err, "InvalidCiphertextException")
	}
	// Correct RSA unwrap and RFC 5649 integrity still must not admit a malformed
	// private key. This short OpenSSL vector also exercises the one-block unwrap.
	short, _ := hex.DecodeString("466f7250617369")
	_, err := c.ImportKeyMaterial(t.Context(), kmsImportRequest(t, k.KeyId, p, short, types.AlgorithmSpecRsaAesKeyWrapSha256))
	assertAPIError(t, err, "InvalidCiphertextException")
	if _, err := c.ImportKeyMaterial(t.Context(), in); err != nil {
		t.Fatal("valid import failed after rejected mutations", err)
	}
}
