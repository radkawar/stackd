package secretsmanager

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"slices"

	"stackd/internal/awswire"
)

// DataKeys is the KMS boundary. Implementations retain the request principal and
// set kms:ViaService; key operations join the current resource transaction.
type DataKeys interface {
	GenerateDataKey(context.Context, string, map[string]string) ([]byte, []byte, string, *awswire.Error)
	Encrypt(context.Context, string, []byte, map[string]string) ([]byte, string, *awswire.Error)
	Decrypt(context.Context, []byte, map[string]string) ([]byte, string, *awswire.Error)
	EnsureServiceKey(context.Context, string) (string, *awswire.Error)
}

func encryptionContext(secret SecretRecord, versionID string) map[string]string {
	return map[string]string{"SecretARN": secret.ARN, "SecretVersionId": versionID}
}

func (s *Service) encryptionKey(ctx context.Context, configured string) (string, error) {
	if s.keys == nil {
		return "", failure("InternalServiceError", "Secrets Manager encryption is not configured.")
	}
	if configured != "" {
		return configured, nil
	}
	key, rejected := s.keys.EnsureServiceKey(ctx, "secretsmanager")
	if rejected != nil {
		return "", keyFailure(rejected, false)
	}
	return key, nil
}

func (s *Service) validateKey(ctx context.Context, secret SecretRecord, keyID string) error {
	id, err := s.encryptionKey(ctx, keyID)
	if err != nil {
		return err
	}
	ec := encryptionContext(secret, "RequestToValidateKeyAccess")
	plain, wrapped, _, rejected := s.keys.GenerateDataKey(ctx, id, ec)
	clear(plain)
	if rejected != nil {
		return validationKeyFailure(rejected)
	}
	plain, _, rejected = s.keys.Decrypt(ctx, wrapped, ec)
	clear(plain)
	if rejected != nil {
		return validationKeyFailure(rejected)
	}
	return nil
}

func validationKeyFailure(err *awswire.Error) error {
	if err.Code == "AccessDenied" || err.Code == "AccessDeniedException" {
		return keyFailure(err, false)
	}
	return failure("InvalidParameterException", "The specified KMS key cannot be used to encrypt or decrypt this secret.")
}

func (s *Service) sealVersion(ctx context.Context, secret SecretRecord, versionID string, plain []byte) (SealedValue, error) {
	key, err := s.encryptionKey(ctx, secret.KMSKeyID)
	if err != nil {
		return SealedValue{}, err
	}
	dataKey, wrapped, arn, rejected := s.keys.GenerateDataKey(ctx, key, encryptionContext(secret, versionID))
	if rejected != nil {
		return SealedValue{}, keyFailure(rejected, false)
	}
	defer clear(dataKey)
	block, err := aes.NewCipher(dataKey)
	if err != nil {
		return SealedValue{}, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return SealedValue{}, err
	}
	nonce := make([]byte, aead.NonceSize(), aead.NonceSize()+len(plain)+aead.Overhead())
	_, _ = rand.Read(nonce)
	payload := aead.Seal(nonce, nonce, plain, nil)
	if secret.KMSKeyID == "" {
		arn = "DefaultEncryptionKey"
	}
	return SealedValue{KeyID: arn, WrappedKey: wrapped, Payload: payload}, nil
}

func (s *Service) openVersion(r Reader, secret SecretRecord, version VersionRecord) ([]byte, error) {
	if s.keys == nil {
		return nil, failure("InternalServiceError", "Secrets Manager encryption is not configured.")
	}
	values, err := r.EncryptedVersion(version.Key)
	if err != nil {
		return nil, err
	}
	var rejected error
	for _, value := range slices.Backward(values) {
		key, _, denied := s.keys.Decrypt(r.Context(), value.WrappedKey, encryptionContext(secret, version.Key.ID))
		if denied != nil {
			rejected = keyFailure(denied, true)
			continue
		}
		block, err := aes.NewCipher(key)
		clear(key)
		if err != nil {
			return nil, err
		}
		aead, err := cipher.NewGCM(block)
		if err != nil {
			return nil, err
		}
		if len(value.Payload) < aead.NonceSize() {
			return nil, errors.New("truncated encrypted secret value")
		}
		return aead.Open(nil, value.Payload[:aead.NonceSize()], value.Payload[aead.NonceSize():], nil)
	}
	if rejected != nil {
		return nil, rejected
	}
	return nil, errors.New("secret version has no encrypted value")
}

// rewrapVersions adds the new wrapping key without discarding the old encryption.
// Only AWS-owned active stages are re-encrypted on a configured-key change.
func (s *Service) rewrapVersions(tx Transaction, secret SecretRecord, newKey string) error {
	key, err := s.encryptionKey(tx.Context(), newKey)
	if err != nil {
		return err
	}
	versions, err := tx.Versions(secret.Key)
	if err != nil {
		return err
	}
	for _, version := range versions {
		if !slices.Contains(version.Stages, "AWSCURRENT") && !slices.Contains(version.Stages, "AWSPREVIOUS") && !slices.Contains(version.Stages, "AWSPENDING") {
			continue
		}
		values, err := tx.EncryptedVersion(version.Key)
		if err != nil {
			return err
		}
		ec := encryptionContext(secret, version.Key.ID)
		for _, value := range slices.Backward(values) {
			dataKey, _, denied := s.keys.Decrypt(tx.Context(), value.WrappedKey, ec)
			if denied != nil {
				continue
			}
			wrapped, arn, denied := s.keys.Encrypt(tx.Context(), key, dataKey, ec)
			clear(dataKey)
			if denied != nil {
				if denied.Code == "AccessDenied" || denied.Code == "AccessDeniedException" {
					break
				}
				return keyFailure(denied, false)
			}
			if newKey == "" {
				arn = "DefaultEncryptionKey"
			}
			exists := false
			for _, previous := range values {
				if previous.KeyID == arn {
					exists = true
					break
				}
			}
			if !exists {
				values = append(values, SealedValue{KeyID: arn, WrappedKey: wrapped, Payload: value.Payload})
				if err := tx.PutEncryptedVersion(version.Key, values); err != nil {
					return err
				}
			}
			break
		}
	}
	return nil
}

func keyFailure(err *awswire.Error, reading bool) error {
	if err.Code == "AccessDenied" || err.Code == "AccessDeniedException" {
		return failure("AccessDeniedException", "Access to KMS is not allowed")
	}
	if reading {
		return failure("DecryptionFailure", "Secrets Manager can't decrypt the protected secret value using the provided KMS key.")
	}
	return failure("EncryptionFailure", "Secrets Manager can't encrypt the protected secret value using the provided KMS key.")
}
