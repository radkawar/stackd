package kms

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	sdkkms "github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
)

func TestSDKRSADataKeyPairs(t *testing.T) {
	c := sdkClient(t, New(), rootMetadata("111111111111", "us-east-1", "aws"))
	key := createSDKKey(t, c)
	ec := map[string]string{"purpose": "offline signing"}
	for _, spec := range []types.DataKeyPairSpec{types.DataKeyPairSpecRsa2048, types.DataKeyPairSpecRsa3072, types.DataKeyPairSpecRsa4096} {
		t.Run(string(spec), func(t *testing.T) {
			pair, err := c.GenerateDataKeyPair(t.Context(), &sdkkms.GenerateDataKeyPairInput{KeyId: key.KeyId, KeyPairSpec: spec, EncryptionContext: ec})
			if err != nil {
				t.Fatal(err)
			}
			if pair.KeyPairSpec != spec || aws.ToString(pair.KeyId) != aws.ToString(key.Arn) || aws.ToString(pair.KeyMaterialId) != aws.ToString(key.CurrentKeyMaterialId) {
				t.Fatal("data key pair metadata differs from AWS")
			}
			decoded, err := c.Decrypt(t.Context(), &sdkkms.DecryptInput{CiphertextBlob: pair.PrivateKeyCiphertextBlob, EncryptionContext: ec})
			if err != nil || !bytes.Equal(decoded.Plaintext, pair.PrivateKeyPlaintext) {
				t.Fatal("encrypted private key round trip", err)
			}
			checkRSAKeyPair(t, pair.PublicKey, pair.PrivateKeyPlaintext, rsaBits(string(spec)))
			clear(pair.PrivateKeyPlaintext)
			clear(decoded.Plaintext)
			_, err = c.Decrypt(t.Context(), &sdkkms.DecryptInput{CiphertextBlob: pair.PrivateKeyCiphertextBlob})
			requireCode(t, err, "InvalidCiphertextException")
			wrapped, err := c.GenerateDataKeyPairWithoutPlaintext(t.Context(), &sdkkms.GenerateDataKeyPairWithoutPlaintextInput{KeyId: key.KeyId, KeyPairSpec: spec, EncryptionContext: ec})
			if err != nil {
				t.Fatal(err)
			}
			if wrapped.KeyPairSpec != spec || aws.ToString(wrapped.KeyId) != aws.ToString(key.Arn) || aws.ToString(wrapped.KeyMaterialId) != aws.ToString(key.CurrentKeyMaterialId) || bytes.Equal(wrapped.PublicKey, pair.PublicKey) {
				t.Fatal("data key pairs must be independent, with the wrapping key's metadata")
			}
			decoded, err = c.Decrypt(t.Context(), &sdkkms.DecryptInput{CiphertextBlob: wrapped.PrivateKeyCiphertextBlob, EncryptionContext: ec})
			if err != nil {
				t.Fatal(err)
			}
			checkRSAKeyPair(t, wrapped.PublicKey, decoded.Plaintext, rsaBits(string(spec)))
			clear(decoded.Plaintext)
			_, err = c.GenerateDataKeyPair(t.Context(), &sdkkms.GenerateDataKeyPairInput{KeyId: key.KeyId, KeyPairSpec: spec, DryRun: aws.Bool(true)})
			requireCode(t, err, "DryRunOperationException")
			_, err = c.GenerateDataKeyPairWithoutPlaintext(t.Context(), &sdkkms.GenerateDataKeyPairWithoutPlaintextInput{KeyId: key.KeyId, KeyPairSpec: spec, DryRun: aws.Bool(true)})
			requireCode(t, err, "DryRunOperationException")
		})
	}
	listed, err := c.ListKeys(t.Context(), &sdkkms.ListKeysInput{})
	if err != nil || len(listed.Keys) != 1 {
		t.Fatal("data keys must not be retained as KMS resources", err)
	}
	asymmetric := createAsymmetricSDKKey(t, c, types.KeySpecRsa2048, types.KeyUsageTypeEncryptDecrypt)
	_, err = c.GenerateDataKeyPair(t.Context(), &sdkkms.GenerateDataKeyPairInput{KeyId: asymmetric.KeyId, KeyPairSpec: types.DataKeyPairSpecRsa2048})
	readCryptoCapture(t, "rsa").requireError(t, err, "data_key_pair_asymmetric_master", types.KeySpecRsa2048, types.KeyUsageTypeEncryptDecrypt, "", false)
	if _, err := c.DisableKey(t.Context(), &sdkkms.DisableKeyInput{KeyId: key.KeyId}); err != nil {
		t.Fatal(err)
	}
	_, err = c.GenerateDataKeyPair(t.Context(), &sdkkms.GenerateDataKeyPairInput{KeyId: key.KeyId, KeyPairSpec: types.DataKeyPairSpecRsa2048, DryRun: aws.Bool(true)})
	requireCode(t, err, "DisabledException")
}

func checkRSAKeyPair(t *testing.T, public, private []byte, bits int) {
	t.Helper()
	decoded, err := x509.ParsePKCS8PrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	key, ok := decoded.(*rsa.PrivateKey)
	if !ok {
		t.Fatalf("private key is %T", decoded)
	}
	if err := key.Validate(); err != nil {
		t.Fatal(err)
	}
	if key.N.BitLen() != bits || !key.PublicKey.Equal(publicRSAKey(t, public)) {
		t.Fatal("PKCS8 private key does not match its SPKI public key or requested size")
	}
}
