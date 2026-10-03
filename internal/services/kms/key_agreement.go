package kms

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"

	kmsapi "stackd/internal/awsapi/kms"
	"stackd/internal/awswire"
)

func (s *Service) deriveSharedSecret(ctx context.Context, in *kmsapi.DeriveSharedSecretInput) (*kmsapi.DeriveSharedSecretOutput, *awswire.Error) {
	// TODO: Comeback capture and enforce ECC regional quotas, key/grant propagation, remaining authorization/error precedence and noncommercial partition behavior before KMS completion.
	if in.Recipient != nil {
		return nil, failure("UnsupportedOperationException", "Recipient attestation is not implemented.")
	}
	ctx = withConditions(withGrantTokens(ctx, in.GrantTokens), map[string][]string{"kms:KeyAgreementAlgorithm": {value(in.KeyAgreementAlgorithm)}})
	k, err := s.resolveAuthorized(ctx, value(in.KeyId), true)
	if err != nil {
		return nil, err
	}
	if err := usable(k); err != nil {
		return nil, err
	}
	if !keyAgreementSpec(k.Spec) || k.Usage != "KEY_AGREEMENT" {
		return nil, failure("InvalidKeyUsageException", "The key does not support ECDH key agreement.")
	}
	decoded, parseErr := x509.ParsePKIXPublicKey(in.PublicKey)
	if parseErr != nil {
		return nil, failure("ValidationException", "")
	}
	peer, ok := decoded.(*ecdsa.PublicKey)
	if !ok {
		return nil, failure("ValidationException", "")
	}
	public, parseErr := peer.ECDH()
	if parseErr != nil {
		return nil, failure("ValidationException", "")
	}
	material, err := asymmetricPrivate(k)
	if err != nil {
		return nil, err
	}
	private, ok := material.(*ecdsa.PrivateKey)
	if !ok {
		return nil, failure("KMSInternalException", "Stored key material is not an EC private key.")
	}
	local, convertErr := private.ECDH()
	if convertErr != nil {
		return nil, failure("KMSInternalException", "Unable to initialize ECDH key material.")
	}
	secret, deriveErr := local.ECDH(public)
	if deriveErr != nil {
		return nil, failure("ValidationException", "")
	}
	if isTrue(in.DryRun) {
		clear(secret)
		return nil, dryRun()
	}
	return &kmsapi.DeriveSharedSecretOutput{KeyId: ptr(kmsapi.KeyIdType(k.arn)), KeyOrigin: ptr(kmsapi.OriginType(k.Origin)), KeyAgreementAlgorithm: in.KeyAgreementAlgorithm, SharedSecret: secret}, nil
}
