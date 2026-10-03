package kms

import (
	"context"
	"crypto/rand"

	kmsapi "stackd/internal/awsapi/kms"
	"stackd/internal/awswire"
)

func (s *Service) registerCrypto() {
	register(s, "Encrypt", s.encryptOperation)
	register(s, "Decrypt", s.decryptOperation)
	register(s, "ReEncrypt", s.reEncrypt)
	register(s, "GenerateDataKey", s.generateDataKey)
	register(s, "GenerateDataKeyWithoutPlaintext", s.generateDataKeyWithoutPlaintext)
	register(s, "GenerateRandom", s.generateRandom)
	register(s, "GenerateMac", s.generateMAC)
	register(s, "VerifyMac", s.verifyMAC)
	register(s, "GetPublicKey", s.getPublicKey)
	register(s, "Sign", s.sign)
	register(s, "Verify", s.verify)
	register(s, "GenerateDataKeyPair", s.generateDataKeyPair)
	register(s, "GenerateDataKeyPairWithoutPlaintext", s.generateDataKeyPairWithoutPlaintext)
	register(s, "DeriveSharedSecret", s.deriveSharedSecret)
}

func dryRun() *awswire.Error {
	return failure("DryRunOperationException", "The request would have succeeded, but DryRun was specified.")
}

func (s *Service) encryptOperation(ctx context.Context, in *kmsapi.EncryptInput) (*kmsapi.EncryptOutput, *awswire.Error) {
	ctx = withGrantTokens(ctx, in.GrantTokens)
	algorithm := encryptionAlgorithm(in.EncryptionAlgorithm)
	context := encryptionContext(in.EncryptionContext)
	ctx = withEncryptionAction(ctx, "Encrypt", context, algorithm)
	k, err := s.resolveAuthorized(ctx, value(in.KeyId), true)
	if err != nil {
		return nil, err
	}
	blob, err := sealWithAlgorithm(k, in.Plaintext, context, algorithm)
	if err != nil {
		return nil, err
	}
	if isTrue(in.DryRun) {
		return nil, dryRun()
	}
	return &kmsapi.EncryptOutput{CiphertextBlob: blob, KeyId: ptr(kmsapi.KeyIdType(k.arn)), EncryptionAlgorithm: ptr(kmsapi.EncryptionAlgorithmSpec(algorithm))}, nil
}

func (s *Service) decryptOperation(ctx context.Context, in *kmsapi.DecryptInput) (*kmsapi.DecryptOutput, *awswire.Error) {
	ctx = withGrantTokens(ctx, in.GrantTokens)
	if in.Recipient != nil {
		return nil, failure("UnsupportedOperationException", "Recipient attestation is not implemented.")
	}
	algorithm := encryptionAlgorithm(in.EncryptionAlgorithm)
	context := encryptionContext(in.EncryptionContext)
	ctx = withEncryptionAction(ctx, "Decrypt", context, algorithm)
	if len(in.DryRunModifiers) != 0 {
		if !isTrue(in.DryRun) {
			return nil, failure("ValidationException", "DryRunModifiers can only be specified when DryRun is true")
		}
		for _, modifier := range in.DryRunModifiers {
			if modifier != kmsapi.DryRunModifierTypeIGNORE_CIPHERTEXT {
				return nil, failure("ValidationException", "Invalid dry-run modifier.")
			}
		}
		if value(in.KeyId) == "" {
			return nil, failure("ValidationException", "KeyId must not be null")
		}
		if err := validateContext(context); err != nil {
			return nil, err
		}
		if algorithm != "SYMMETRIC_DEFAULT" && len(context) != 0 {
			return nil, failure("ValidationException", "EncryptionContext is not supported when encrypting/decrypting with asymmetric CMKs.")
		}
		k, err := s.resolveAuthorized(ctx, value(in.KeyId), true)
		if err != nil {
			return nil, err
		}
		if err := usable(k); err != nil {
			return nil, err
		}
		validAlgorithm := algorithm == "SYMMETRIC_DEFAULT" && k.Spec == "SYMMETRIC_DEFAULT" ||
			(algorithm == "RSAES_OAEP_SHA_1" || algorithm == "RSAES_OAEP_SHA_256") && rsaBits(k.Spec) != 0
		if k.Usage != "ENCRYPT_DECRYPT" || !validAlgorithm {
			return nil, failure("InvalidKeyUsageException", "The key does not support the requested encryption algorithm.")
		}
		return nil, dryRun()
	}
	plaintext, k, material, err := s.open(ctx, in.CiphertextBlob, context, value(in.KeyId), algorithm)
	if err != nil {
		return nil, err
	}
	if isTrue(in.DryRun) {
		clear(plaintext)
		return nil, dryRun()
	}
	return &kmsapi.DecryptOutput{Plaintext: plaintext, KeyId: ptr(kmsapi.KeyIdType(k.arn)), EncryptionAlgorithm: ptr(kmsapi.EncryptionAlgorithmSpec(algorithm)), KeyMaterialId: keyMaterialID(k, material)}, nil
}

func (s *Service) reEncrypt(ctx context.Context, in *kmsapi.ReEncryptInput) (*kmsapi.ReEncryptOutput, *awswire.Error) {
	ctx = withGrantTokens(ctx, in.GrantTokens)
	if len(in.DryRunModifiers) != 0 {
		return nil, failure("UnsupportedOperationException", "Dry-run modifiers are not implemented.")
	}
	sourceAlgorithm := encryptionAlgorithm(in.SourceEncryptionAlgorithm)
	destinationAlgorithm := encryptionAlgorithm(in.DestinationEncryptionAlgorithm)
	dest, err := s.resolve(ctx, value(in.DestinationKeyId), true)
	if err != nil {
		return nil, err
	}
	sourceContext := encryptionContext(in.SourceEncryptionContext)
	plaintext, source, sourceMaterial, err := s.open(withReEncryptAction(ctx, "ReEncryptFrom", sourceContext, sourceAlgorithm, dest.arn), in.CiphertextBlob, sourceContext, value(in.SourceKeyId), sourceAlgorithm)
	if err != nil {
		return nil, err
	}
	defer clear(plaintext)
	destContext := encryptionContext(in.DestinationEncryptionContext)
	if err := s.authorizeResolvedKey(withReEncryptAction(ctx, "ReEncryptTo", destContext, destinationAlgorithm, source.arn), dest, value(in.DestinationKeyId)); err != nil {
		return nil, err
	}
	blob, err := sealWithAlgorithm(dest, plaintext, destContext, destinationAlgorithm)
	if err != nil {
		return nil, err
	}
	if isTrue(in.DryRun) {
		return nil, dryRun()
	}
	return &kmsapi.ReEncryptOutput{CiphertextBlob: blob, SourceKeyId: ptr(kmsapi.KeyIdType(source.arn)), KeyId: ptr(kmsapi.KeyIdType(dest.arn)), SourceEncryptionAlgorithm: ptr(kmsapi.EncryptionAlgorithmSpec(sourceAlgorithm)), DestinationEncryptionAlgorithm: ptr(kmsapi.EncryptionAlgorithmSpec(destinationAlgorithm)), SourceKeyMaterialId: keyMaterialID(source, sourceMaterial), DestinationKeyMaterialId: keyMaterialID(dest, dest.currentMaterial())}, nil
}

func withReEncryptAction(ctx context.Context, action string, encryptionContext map[string]string, algorithm, otherKeyARN string) context.Context {
	ctx = withEncryptionAction(ctx, action, encryptionContext, algorithm)
	request, _ := ctx.Value(actionContextKey{}).(actionContext)
	request.reEncryptOtherKeyARN = otherKeyARN
	return context.WithValue(ctx, actionContextKey{}, request)
}

func dataKeySize(spec *kmsapi.DataKeySpec, size *kmsapi.NumberOfBytesType) (int, *awswire.Error) {
	if (spec == nil) == (size == nil) {
		return 0, failure("ValidationException", "Specify exactly one of KeySpec or NumberOfBytes.")
	}
	if spec != nil {
		switch value(spec) {
		case "AES_128":
			return 16, nil
		case "AES_256":
			return 32, nil
		default:
			return 0, failure("ValidationException", "KeySpec must be AES_128 or AES_256.")
		}
	}
	if *size < 1 || *size > 1024 {
		return 0, failure("ValidationException", "NumberOfBytes must be between 1 and 1024.")
	}
	return int(*size), nil
}

func (s *Service) generateDataKey(ctx context.Context, in *kmsapi.GenerateDataKeyInput) (*kmsapi.GenerateDataKeyOutput, *awswire.Error) {
	ctx = withGrantTokens(ctx, in.GrantTokens)
	if in.Recipient != nil {
		return nil, failure("UnsupportedOperationException", "Recipient attestation is not implemented.")
	}
	size, err := dataKeySize(in.KeySpec, in.NumberOfBytes)
	if err != nil {
		return nil, err
	}
	context := encryptionContext(in.EncryptionContext)
	plaintext, blob, k, err := s.dataKey(withAction(ctx, "GenerateDataKey", context), value(in.KeyId), context, size)
	if err != nil {
		return nil, err
	}
	if isTrue(in.DryRun) {
		clear(plaintext)
		return nil, dryRun()
	}
	return &kmsapi.GenerateDataKeyOutput{Plaintext: plaintext, CiphertextBlob: blob, KeyId: ptr(kmsapi.KeyIdType(k.arn)), KeyMaterialId: keyMaterialID(k, k.currentMaterial())}, nil
}

func (s *Service) generateDataKeyWithoutPlaintext(ctx context.Context, in *kmsapi.GenerateDataKeyWithoutPlaintextInput) (*kmsapi.GenerateDataKeyWithoutPlaintextOutput, *awswire.Error) {
	ctx = withGrantTokens(ctx, in.GrantTokens)
	size, err := dataKeySize(in.KeySpec, in.NumberOfBytes)
	if err != nil {
		return nil, err
	}
	context := encryptionContext(in.EncryptionContext)
	plaintext, blob, k, err := s.dataKey(withAction(ctx, "GenerateDataKeyWithoutPlaintext", context), value(in.KeyId), context, size)
	if err != nil {
		return nil, err
	}
	clear(plaintext)
	if isTrue(in.DryRun) {
		return nil, dryRun()
	}
	return &kmsapi.GenerateDataKeyWithoutPlaintextOutput{CiphertextBlob: blob, KeyId: ptr(kmsapi.KeyIdType(k.arn)), KeyMaterialId: keyMaterialID(k, k.currentMaterial())}, nil
}

func (s *Service) generateRandom(_ context.Context, in *kmsapi.GenerateRandomInput) (*kmsapi.GenerateRandomOutput, *awswire.Error) {
	if in.CustomKeyStoreId != nil || in.Recipient != nil {
		return nil, failure("UnsupportedOperationException", "Custom key stores and recipient attestation are not implemented.")
	}
	size := 32
	if in.NumberOfBytes != nil {
		size = int(*in.NumberOfBytes)
	}
	if size < 1 || size > 1024 {
		return nil, failure("ValidationException", "NumberOfBytes must be between 1 and 1024.")
	}
	plaintext := make([]byte, size)
	_, _ = rand.Read(plaintext)
	return &kmsapi.GenerateRandomOutput{Plaintext: plaintext}, nil
}
