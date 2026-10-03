package stackd_test

import (
	"bytes"
	"path/filepath"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"

	"stackd/storage"
)

func TestSQLiteKMSRetainsSigningAndMACMaterial(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.sqlite")
	c, close := openSQLiteCloud(t, path, storage.NewMemory(), nil)
	owner := c.kms("test", "test", "")
	message := []byte("signature survives database recovery")
	var signatures []*kms.SignOutput
	var publicKeys [][]byte
	for _, algorithm := range []struct {
		spec types.KeySpec
		sign types.SigningAlgorithmSpec
	}{{types.KeySpecRsa2048, types.SigningAlgorithmSpecRsassaPssSha256}, {types.KeySpecEccNistP256, types.SigningAlgorithmSpecEcdsaSha256}, {types.KeySpecMlDsa44, types.SigningAlgorithmSpecMlDsaShake256}} {
		key, err := owner.CreateKey(t.Context(), &kms.CreateKeyInput{KeySpec: algorithm.spec, KeyUsage: types.KeyUsageTypeSignVerify})
		if err != nil {
			t.Fatal(err)
		}
		public, err := owner.GetPublicKey(t.Context(), &kms.GetPublicKeyInput{KeyId: key.KeyMetadata.KeyId})
		if err != nil {
			t.Fatal(err)
		}
		publicKeys = append(publicKeys, public.PublicKey)
		signature, err := owner.Sign(t.Context(), &kms.SignInput{KeyId: key.KeyMetadata.KeyId, Message: message, SigningAlgorithm: algorithm.sign})
		if err != nil {
			t.Fatal(err)
		}
		signatures = append(signatures, signature)
	}
	macKey, err := owner.CreateKey(t.Context(), &kms.CreateKeyInput{KeySpec: types.KeySpecHmac256, KeyUsage: types.KeyUsageTypeGenerateVerifyMac})
	if err != nil {
		t.Fatal(err)
	}
	mac, err := owner.GenerateMac(t.Context(), &kms.GenerateMacInput{KeyId: macKey.KeyMetadata.KeyId, MacAlgorithm: types.MacAlgorithmSpecHmacSha256, Message: message})
	if err != nil {
		t.Fatal(err)
	}
	close()
	c, _ = openSQLiteCloud(t, path, storage.NewMemory(), nil)
	owner = c.kms("test", "test", "")
	for i, signature := range signatures {
		public, err := owner.GetPublicKey(t.Context(), &kms.GetPublicKeyInput{KeyId: signature.KeyId})
		if err != nil || !bytes.Equal(public.PublicKey, publicKeys[i]) {
			t.Fatal("reopening replaced an asymmetric key", err)
		}
		verified, err := owner.Verify(t.Context(), &kms.VerifyInput{KeyId: signature.KeyId, Message: message, Signature: signature.Signature, SigningAlgorithm: signature.SigningAlgorithm})
		if err != nil || !verified.SignatureValid {
			t.Fatal("reopening lost signing material", err)
		}
		if _, err := owner.Sign(t.Context(), &kms.SignInput{KeyId: signature.KeyId, Message: message, SigningAlgorithm: signature.SigningAlgorithm}); err != nil {
			t.Fatal("restored private key cannot sign", err)
		}
	}
	verified, err := owner.VerifyMac(t.Context(), &kms.VerifyMacInput{KeyId: mac.KeyId, MacAlgorithm: mac.MacAlgorithm, Message: message, Mac: mac.Mac})
	if err != nil || !verified.MacValid {
		t.Fatal("reopening lost HMAC material", err)
	}
	again, err := owner.GenerateMac(t.Context(), &kms.GenerateMacInput{KeyId: mac.KeyId, MacAlgorithm: mac.MacAlgorithm, Message: message})
	if err != nil || !bytes.Equal(again.Mac, mac.Mac) {
		t.Fatal("restored HMAC key changed", err)
	}
	// Equal identifiers in another account do not resolve to the owner's key.
	_, err = c.kms("111111111111", "test", "").GenerateMac(t.Context(), &kms.GenerateMacInput{KeyId: macKey.KeyMetadata.KeyId, MacAlgorithm: mac.MacAlgorithm, Message: message})
	assertAPIError(t, err, "NotFoundException")
}
