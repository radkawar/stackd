package kms

import (
	"context"

	kmsapi "stackd/internal/awsapi/kms"
	"stackd/internal/awswire"
)

func (s *Service) dataKeyPair(ctx context.Context, keyID, spec string, encryptionContext map[string]string, dry bool) (*kmsapi.GenerateDataKeyPairOutput, *awswire.Error) {
	if !asymmetricSpec(spec) {
		// TODO: Comeback implement SM2 data-key-pair generation and recipient attestation workflow.
		return nil, failure("UnsupportedOperationException", "This data key pair specification is not implemented.")
	}
	ctx = withConditions(ctx, map[string][]string{"kms:DataKeyPairSpec": {spec}})
	k, err := s.resolveAuthorized(ctx, keyID, true)
	if err != nil {
		return nil, err
	}
	aead, err := prepareSymmetricEncryption(k, encryptionContext)
	if err != nil {
		return nil, err
	}
	if dry {
		return nil, dryRun()
	}
	private, public, err := generateAsymmetric(spec)
	if err != nil {
		return nil, err
	}
	blob, err := sealPrepared(aead, k.arn, k.currentMaterial().ID, private, encryptionContext)
	if err != nil {
		clear(private)
		return nil, err
	}
	return &kmsapi.GenerateDataKeyPairOutput{KeyId: ptr(kmsapi.KeyIdType(k.arn)), KeyMaterialId: keyMaterialID(k, k.currentMaterial()), KeyPairSpec: ptr(kmsapi.DataKeyPairSpec(spec)), PrivateKeyPlaintext: private, PrivateKeyCiphertextBlob: blob, PublicKey: public}, nil
}

func (s *Service) generateDataKeyPair(ctx context.Context, in *kmsapi.GenerateDataKeyPairInput) (*kmsapi.GenerateDataKeyPairOutput, *awswire.Error) {
	if in.Recipient != nil {
		return nil, failure("UnsupportedOperationException", "Recipient attestation is not implemented.")
	}
	encryptionContext := encryptionContext(in.EncryptionContext)
	ctx = withAction(withGrantTokens(ctx, in.GrantTokens), "GenerateDataKeyPair", encryptionContext)
	return s.dataKeyPair(ctx, value(in.KeyId), value(in.KeyPairSpec), encryptionContext, isTrue(in.DryRun))
}

func (s *Service) generateDataKeyPairWithoutPlaintext(ctx context.Context, in *kmsapi.GenerateDataKeyPairWithoutPlaintextInput) (*kmsapi.GenerateDataKeyPairWithoutPlaintextOutput, *awswire.Error) {
	encryptionContext := encryptionContext(in.EncryptionContext)
	ctx = withAction(withGrantTokens(ctx, in.GrantTokens), "GenerateDataKeyPairWithoutPlaintext", encryptionContext)
	out, err := s.dataKeyPair(ctx, value(in.KeyId), value(in.KeyPairSpec), encryptionContext, isTrue(in.DryRun))
	if err != nil {
		return nil, err
	}
	clear(out.PrivateKeyPlaintext)
	return &kmsapi.GenerateDataKeyPairWithoutPlaintextOutput{KeyId: out.KeyId, KeyMaterialId: out.KeyMaterialId, KeyPairSpec: out.KeyPairSpec, PrivateKeyCiphertextBlob: out.PrivateKeyCiphertextBlob, PublicKey: out.PublicKey}, nil
}
