package kms

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"

	kmsapi "stackd/internal/awsapi/kms"
	"stackd/internal/awswire"
)

func encryptionAlgorithm(in *kmsapi.EncryptionAlgorithmSpec) string {
	if value(in) == "" {
		return "SYMMETRIC_DEFAULT"
	}
	return value(in)
}

func withEncryptionAction(ctx context.Context, action string, encryptionContext map[string]string, algorithm string) context.Context {
	return withConditions(withAction(ctx, action, encryptionContext), map[string][]string{"kms:EncryptionAlgorithm": {algorithm}})
}

func rsaEncryptionKey(k *key, algorithm string, encryptionContext map[string]string) (*rsa.PrivateKey, crypto.Hash, *awswire.Error) {
	if err := usable(k); err != nil {
		return nil, 0, err
	}
	if rsaBits(k.Spec) == 0 || k.Usage != "ENCRYPT_DECRYPT" {
		return nil, 0, failure("InvalidKeyUsageException", "The key does not support RSA encryption.")
	}
	if len(encryptionContext) != 0 {
		return nil, 0, failure("ValidationException", "EncryptionContext is not supported when encrypting/decrypting with asymmetric CMKs.")
	}
	for _, candidate := range rsaEncryptionAlgorithms {
		if string(candidate.name) == algorithm {
			private, err := rsaPrivate(k)
			return private, candidate.hash, err
		}
	}
	return nil, 0, failure("InvalidKeyUsageException", fmt.Sprintf("Algorithm %s is incompatible with key spec %s.", algorithm, k.Spec))
}

func sealWithAlgorithm(k *key, plaintext []byte, encryptionContext map[string]string, algorithm string) ([]byte, *awswire.Error) {
	if algorithm == "SYMMETRIC_DEFAULT" {
		return seal(k, plaintext, encryptionContext)
	}
	private, hash, err := rsaEncryptionKey(k, algorithm, encryptionContext)
	if err != nil {
		return nil, err
	}
	blob, encryptErr := rsa.EncryptOAEP(hash.New(), rand.Reader, &private.PublicKey, plaintext, nil)
	if errors.Is(encryptErr, rsa.ErrMessageTooLong) {
		return nil, failure("ValidationException", fmt.Sprintf("Algorithm %s and key spec %s cannot encrypt data larger than %d bytes.", algorithm, k.Spec, private.Size()-2*hash.Size()-2))
	}
	if encryptErr != nil {
		return nil, failure("KMSInternalException", "Unable to encrypt with RSA key material.")
	}
	return blob, nil
}

func (s *Service) open(ctx context.Context, blob []byte, encryptionContext map[string]string, keyID, algorithm string) ([]byte, *key, *KeyMaterialRecord, *awswire.Error) {
	if algorithm == "SYMMETRIC_DEFAULT" {
		return s.openSymmetric(ctx, blob, encryptionContext, keyID)
	}
	if keyID == "" {
		return nil, nil, nil, failure("ValidationException", "KeyId must not be null")
	}
	k, err := s.resolveAuthorized(ctx, keyID, true)
	if err != nil {
		return nil, nil, nil, err
	}
	private, hash, err := rsaEncryptionKey(k, algorithm, encryptionContext)
	if err != nil {
		return nil, nil, nil, err
	}
	plaintext, decryptErr := rsa.DecryptOAEP(hash.New(), rand.Reader, private, blob, nil)
	if decryptErr != nil {
		return nil, nil, nil, failure("InvalidCiphertextException", "")
	}
	return plaintext, k, k.currentMaterial(), nil
}

func keyMaterialID(k *key, material *KeyMaterialRecord) *kmsapi.BackingKeyIdType {
	if k.Spec != "SYMMETRIC_DEFAULT" || material == nil || material.ID == "" {
		return nil
	}
	return ptr(kmsapi.BackingKeyIdType(material.ID))
}
