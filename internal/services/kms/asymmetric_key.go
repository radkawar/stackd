package kms

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"

	kmsapi "stackd/internal/awsapi/kms"
	"stackd/internal/awswire"
)

func nistCurve(spec string) elliptic.Curve {
	switch spec {
	case "ECC_NIST_P256":
		return elliptic.P256()
	case "ECC_NIST_P384":
		return elliptic.P384()
	case "ECC_NIST_P521":
		return elliptic.P521()
	default:
		return nil
	}
}

func asymmetricSpec(spec string) bool {
	return rsaBits(spec) != 0 || nistCurve(spec) != nil || spec == "ECC_SECG_P256K1" || spec == "ECC_NIST_EDWARDS25519" || mldsaSpec(spec)
}

func keyAgreementSpec(spec string) bool {
	return nistCurve(spec) != nil
}

func generateAsymmetric(spec string) ([]byte, []byte, *awswire.Error) {
	var private crypto.Signer
	var err error
	switch {
	case rsaBits(spec) != 0:
		private, err = rsa.GenerateKey(rand.Reader, rsaBits(spec))
	case mldsaSpec(spec):
		private = &mldsaSigner{key: mldsaParameterSets[spec].generate()}
	case spec == "ECC_NIST_EDWARDS25519":
		_, private, err = ed25519.GenerateKey(rand.Reader)
	case spec == "ECC_SECG_P256K1":
		var generated *secp256k1.PrivateKey
		generated, err = secp256k1.GeneratePrivateKey()
		private = &secp256k1Signer{key: generated}
	case nistCurve(spec) != nil:
		private, err = ecdsa.GenerateKey(nistCurve(spec), rand.Reader)
	default:
		return nil, nil, failure("UnsupportedOperationException", "This key specification is not implemented.")
	}
	if err != nil {
		return nil, nil, failure("KMSInternalException", "Unable to generate asymmetric key material.")
	}
	encoded, err := marshalAsymmetricPrivate(private)
	if err != nil {
		return nil, nil, failure("KMSInternalException", "Unable to encode asymmetric private key.")
	}
	public, err := marshalAsymmetricPublic(private.Public())
	if err != nil {
		clear(encoded)
		return nil, nil, failure("KMSInternalException", "Unable to encode asymmetric public key.")
	}
	return encoded, public, nil
}

// asymmetricPrivate decodes the protected PKCS8 representation at the storage
// boundary. The crypto.Signer contract is shared by RSA, ECDSA and Ed25519.
func asymmetricPrivate(k *key) (crypto.Signer, *awswire.Error) {
	private, err := parseAsymmetricPrivate(k.Spec, k.currentMaterial().Material)
	if err != nil {
		return nil, failure("KMSInternalException", "Unable to decode stored asymmetric key material.")
	}
	return private, nil
}

func (s *Service) getPublicKey(ctx context.Context, in *kmsapi.GetPublicKeyInput) (*kmsapi.GetPublicKeyOutput, *awswire.Error) {
	k, err := s.resolveAuthorized(withGrantTokens(ctx, in.GrantTokens), value(in.KeyId), true)
	if err != nil {
		return nil, err
	}
	if !asymmetricSpec(k.Spec) {
		return nil, failure("UnsupportedOperationException", "")
	}
	// Disabled keys still allow public-key retrieval; deletion blocks it.
	if k.state != "Enabled" && k.state != "Disabled" && k.state != "Updating" {
		return nil, failure("KMSInvalidStateException", "The key is not in a valid state for this operation.")
	}
	private, err := asymmetricPrivate(k)
	if err != nil {
		return nil, err
	}
	public, encodeErr := marshalAsymmetricPublic(private.Public())
	if encodeErr != nil {
		return nil, failure("KMSInternalException", "Unable to encode asymmetric public key.")
	}
	m := metadata(ctx, k)
	return &kmsapi.GetPublicKeyOutput{KeyId: ptr(kmsapi.KeyIdType(k.arn)), KeySpec: m.KeySpec, CustomerMasterKeySpec: m.CustomerMasterKeySpec, KeyUsage: m.KeyUsage, EncryptionAlgorithms: m.EncryptionAlgorithms, SigningAlgorithms: m.SigningAlgorithms, KeyAgreementAlgorithms: m.KeyAgreementAlgorithms, PublicKey: public}, nil
}
