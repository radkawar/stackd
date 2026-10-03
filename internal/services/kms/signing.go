package kms

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"fmt"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	secpecdsa "github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"github.com/metacubex/mldsa/mldsa"

	kmsapi "stackd/internal/awsapi/kms"
	"stackd/internal/awswire"
)

type signingAlgorithm struct {
	name kmsapi.SigningAlgorithmSpec
	hash crypto.Hash
	pss  bool
}

func signingAlgorithms(spec string) []signingAlgorithm {
	if rsaBits(spec) != 0 {
		return rsaSigningAlgorithms
	}
	if mldsaSpec(spec) {
		return []signingAlgorithm{{name: "ML_DSA_SHAKE_256"}}
	}
	switch spec {
	case "ECC_NIST_P256", "ECC_SECG_P256K1":
		return []signingAlgorithm{{"ECDSA_SHA_256", crypto.SHA256, false}}
	case "ECC_NIST_P384":
		return []signingAlgorithm{{"ECDSA_SHA_384", crypto.SHA384, false}}
	case "ECC_NIST_P521":
		return []signingAlgorithm{{"ECDSA_SHA_512", crypto.SHA512, false}}
	case "ECC_NIST_EDWARDS25519":
		return []signingAlgorithm{{"ED25519_PH_SHA_512", crypto.SHA512, false}, {"ED25519_SHA_512", crypto.SHA512, false}}
	default:
		return nil
	}
}

// signingRequest owns authorization, algorithm compatibility and message
// preparation. Sign and Verify consume the same crypto.Signer options.
type signingRequest struct {
	key     *key
	private crypto.Signer
	message []byte
	options crypto.SignerOpts
}

func (s *Service) signingRequest(ctx context.Context, keyID, algorithm, messageType string, message []byte) (*signingRequest, *awswire.Error) {
	if messageType == "" {
		messageType = "RAW"
	}
	ctx = withConditions(ctx, map[string][]string{"kms:SigningAlgorithm": {algorithm}, "kms:MessageType": {messageType}})
	k, err := s.resolveAuthorized(ctx, keyID, true)
	if err != nil {
		return nil, err
	}
	if err := usable(k); err != nil {
		return nil, err
	}
	if k.Usage != "SIGN_VERIFY" {
		return nil, failure("InvalidKeyUsageException", "The key does not support signing and verification.")
	}
	var selected signingAlgorithm
	for _, candidate := range signingAlgorithms(k.Spec) {
		if string(candidate.name) == algorithm {
			selected = candidate
			break
		}
	}
	if selected.name == "" {
		return nil, failure("InvalidKeyUsageException", fmt.Sprintf("Algorithm %s is incompatible with key spec %s.", algorithm, k.Spec))
	}
	digest, options, err := signingMessage(selected, k.Spec, messageType, message)
	if err != nil {
		return nil, err
	}
	private, err := asymmetricPrivate(k)
	if err != nil {
		return nil, err
	}
	return &signingRequest{key: k, private: private, message: digest, options: options}, nil
}

func signingMessage(algorithm signingAlgorithm, spec, messageType string, message []byte) ([]byte, crypto.SignerOpts, *awswire.Error) {
	if algorithm.name == "ML_DSA_SHAKE_256" {
		return mldsaMessage(spec, messageType, message)
	}
	if messageType != "RAW" && messageType != "DIGEST" {
		return nil, nil, failure("ValidationException", fmt.Sprintf("Message type %s is incompatible with key spec %s.", messageType, spec))
	}
	var options crypto.SignerOpts = algorithm.hash
	if algorithm.pss {
		options = &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: algorithm.hash}
	}
	if algorithm.name == "ED25519_SHA_512" {
		if messageType != "RAW" {
			return nil, nil, failure("ValidationException", fmt.Sprintf("Message type %s is incompatible with algorithm %s.", messageType, algorithm.name))
		}
		return message, &ed25519.Options{}, nil
	}
	prehashedEdwards := algorithm.name == "ED25519_PH_SHA_512"
	if prehashedEdwards {
		if messageType != "DIGEST" {
			return nil, nil, failure("ValidationException", fmt.Sprintf("Message type %s is incompatible with algorithm %s.", messageType, algorithm.name))
		}
		options = &ed25519.Options{Hash: crypto.SHA512}
	}
	switch messageType {
	case "RAW":
	case "DIGEST":
		if len(message) != algorithm.hash.Size() {
			return nil, nil, failure("ValidationException", fmt.Sprintf("Digest is invalid length for algorithm %s.", algorithm.name))
		}
		if !prehashedEdwards {
			return message, options, nil
		}
		// AWS performs the Ed25519ph prehash over the caller's digest too.
	}
	hash := algorithm.hash.New()
	_, _ = hash.Write(message)
	return hash.Sum(nil), options, nil
}

func (s *Service) sign(ctx context.Context, in *kmsapi.SignInput) (*kmsapi.SignOutput, *awswire.Error) {
	request, err := s.signingRequest(withGrantTokens(ctx, in.GrantTokens), value(in.KeyId), value(in.SigningAlgorithm), value(in.MessageType), in.Message)
	if err != nil {
		return nil, err
	}
	if isTrue(in.DryRun) {
		return nil, dryRun()
	}
	signature, signErr := request.private.Sign(rand.Reader, request.message, request.options)
	if signErr != nil {
		return nil, failure("KMSInternalException", "Unable to sign with asymmetric key material.")
	}
	return &kmsapi.SignOutput{KeyId: ptr(kmsapi.KeyIdType(request.key.arn)), SigningAlgorithm: in.SigningAlgorithm, Signature: signature}, nil
}

func (s *Service) verify(ctx context.Context, in *kmsapi.VerifyInput) (*kmsapi.VerifyOutput, *awswire.Error) {
	request, err := s.signingRequest(withGrantTokens(ctx, in.GrantTokens), value(in.KeyId), value(in.SigningAlgorithm), value(in.MessageType), in.Message)
	if err != nil {
		return nil, err
	}
	if !verifySignature(request.private.Public(), request.message, in.Signature, request.options) {
		return nil, failure("KMSInvalidSignatureException", "")
	}
	if isTrue(in.DryRun) {
		return nil, dryRun()
	}
	return &kmsapi.VerifyOutput{KeyId: ptr(kmsapi.KeyIdType(request.key.arn)), SigningAlgorithm: in.SigningAlgorithm, SignatureValid: ptr(kmsapi.BooleanType(true))}, nil
}

func verifySignature(public crypto.PublicKey, message, signature []byte, options crypto.SignerOpts) bool {
	switch public := public.(type) {
	case *rsa.PublicKey:
		if pss, ok := options.(*rsa.PSSOptions); ok {
			return rsa.VerifyPSS(public, options.HashFunc(), message, signature, pss) == nil
		}
		return rsa.VerifyPKCS1v15(public, options.HashFunc(), message, signature) == nil
	case *ecdsa.PublicKey:
		return ecdsa.VerifyASN1(public, message, signature)
	case *secp256k1.PublicKey:
		parsed, err := secpecdsa.ParseDERSignature(signature)
		return err == nil && parsed.Verify(message, public)
	case ed25519.PublicKey:
		return ed25519.VerifyWithOptions(public, message, signature, options.(*ed25519.Options)) == nil
	case *mldsa.PublicKey:
		return verifyMLDSA(public, message, signature, options)
	default:
		return false
	}
}
