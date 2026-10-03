package kms

import (
	"context"
	"crypto"
	"crypto/hmac"
	_ "crypto/sha256" // Register SHA-224 and SHA-256 for crypto.Hash.New.
	_ "crypto/sha512" // Register SHA-384 and SHA-512 for crypto.Hash.New.
	"fmt"

	kmsapi "stackd/internal/awsapi/kms"
	"stackd/internal/awswire"
)

// hmacSpec owns the KMS key-spec, MAC algorithm and digest relationship. The
// digest size is also the generated key-material size for these AWS key specs.
func hmacSpec(spec string) (kmsapi.MacAlgorithmSpec, crypto.Hash) {
	switch spec {
	case "HMAC_224":
		return "HMAC_SHA_224", crypto.SHA224
	case "HMAC_256":
		return "HMAC_SHA_256", crypto.SHA256
	case "HMAC_384":
		return "HMAC_SHA_384", crypto.SHA384
	case "HMAC_512":
		return "HMAC_SHA_512", crypto.SHA512
	default:
		return "", 0
	}
}

func (s *Service) calculateMAC(ctx context.Context, keyID, algorithm string, message []byte) (*key, []byte, *awswire.Error) {
	// TODO: Comeback capture and enforce regional HMAC request quotas and remaining key/grant propagation and authorization-error precedence against AWS before KMS completion.
	ctx = withConditions(ctx, map[string][]string{"kms:MacAlgorithm": {algorithm}})
	k, err := s.resolveAuthorized(ctx, keyID, true)
	if err != nil {
		return nil, nil, err
	}
	if err := usable(k); err != nil {
		return nil, nil, err
	}
	want, hash := hmacSpec(k.Spec)
	if k.Usage != "GENERATE_VERIFY_MAC" || hash == 0 {
		return nil, nil, failure("InvalidKeyUsageException", "The key does not support message authentication codes.")
	}
	if string(want) != algorithm {
		return nil, nil, failure("InvalidKeyUsageException", fmt.Sprintf("Algorithm %s is incompatible with key spec %s.", algorithm, k.Spec))
	}
	mac := hmac.New(hash.New, k.currentMaterial().Material)
	_, _ = mac.Write(message)
	return k, mac.Sum(nil), nil
}

func (s *Service) generateMAC(ctx context.Context, in *kmsapi.GenerateMacInput) (*kmsapi.GenerateMacOutput, *awswire.Error) {
	k, mac, err := s.calculateMAC(withGrantTokens(ctx, in.GrantTokens), value(in.KeyId), value(in.MacAlgorithm), in.Message)
	if err != nil {
		return nil, err
	}
	if isTrue(in.DryRun) {
		return nil, dryRun()
	}
	return &kmsapi.GenerateMacOutput{KeyId: ptr(kmsapi.KeyIdType(k.arn)), MacAlgorithm: in.MacAlgorithm, Mac: mac}, nil
}

func (s *Service) verifyMAC(ctx context.Context, in *kmsapi.VerifyMacInput) (*kmsapi.VerifyMacOutput, *awswire.Error) {
	k, mac, err := s.calculateMAC(withGrantTokens(ctx, in.GrantTokens), value(in.KeyId), value(in.MacAlgorithm), in.Message)
	if err != nil {
		return nil, err
	}
	if !hmac.Equal(mac, in.Mac) {
		return nil, failure("KMSInvalidMacException", "")
	}
	if isTrue(in.DryRun) {
		return nil, dryRun()
	}
	return &kmsapi.VerifyMacOutput{KeyId: ptr(kmsapi.KeyIdType(k.arn)), MacAlgorithm: in.MacAlgorithm, MacValid: ptr(kmsapi.BooleanType(true))}, nil
}
