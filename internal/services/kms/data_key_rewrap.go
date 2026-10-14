package kms

import (
	"context"

	"stackd/internal/awswire"
)

// CheckDataKeyRewrap checks envelope-update authority without performing crypto,
// allocating a new data key, changing key state or publishing a fictitious API
// call. A service's final publication can borrow its existing transaction here.
// An empty source identifies a service-owned plaintext data key.
func (s *Service) CheckDataKeyRewrap(ctx context.Context, source, destination string, sourceCipher, destinationCipher []byte, sourceContext, destinationContext map[string]string) *awswire.Error {
	err := s.storage.View(ctx, func(reader Reader) error {
		return s.withWorkingSet(reader, func(ctx context.Context) error {
			dest, wire := s.resolve(ctx, destination, false)
			if wire != nil {
				return wire
			}
			if dest.manager != "CUSTOMER" {
				return failure("InvalidKeyUsageException", "The destination must be a customer-managed KMS key.")
			}
			if wire := rewrapKeyUsable(dest, destinationCipher); wire != nil {
				return wire
			}
			for _, action := range []string{"Encrypt", "GenerateDataKey", "ReEncryptTo"} {
				authority := withReEncryptAction(ctx, action, destinationContext, "SYMMETRIC_DEFAULT", source)
				if action == "GenerateDataKey" {
					authority = withAction(ctx, action, destinationContext)
				}
				if wire := s.authorizeResolvedKey(authority, dest, destination); wire != nil {
					return wire
				}
			}
			if source != "" {
				key, wire := s.resolve(ctx, source, false)
				if wire != nil {
					return wire
				}
				if wire := rewrapKeyUsable(key, sourceCipher); wire != nil {
					return wire
				}
				for _, action := range []string{"Decrypt", "ReEncryptFrom"} {
					authority := withReEncryptAction(ctx, action, sourceContext, "SYMMETRIC_DEFAULT", dest.arn)
					if wire := s.authorizeResolvedKey(authority, key, source); wire != nil {
						return wire
					}
				}
			}
			return s.storageErr
		})
	})
	return transactionError(err)
}

func rewrapKeyUsable(key *key, wrapped []byte) *awswire.Error {
	if wire := usable(key); wire != nil {
		return wire
	}
	if key.Spec != "SYMMETRIC_DEFAULT" || key.Usage != "ENCRYPT_DECRYPT" {
		return failure("InvalidKeyUsageException", "The key does not support symmetric data-key encryption.")
	}
	if len(wrapped) != 0 {
		arn, end, wire := ciphertextKeyID(wrapped)
		if wire != nil {
			return wire
		}
		if arn != key.arn {
			return failure("IncorrectKeyException", "The envelope belongs to another KMS key.")
		}
		id := string(wrapped[end-materialIDLength : end])
		for _, material := range key.Materials {
			if material.ID == id && len(material.Material) != 0 {
				return nil
			}
		}
		return failure("InvalidCiphertextException", "The envelope's key material is no longer available.")
	}
	material := key.currentMaterial()
	if material == nil || len(material.Material) == 0 {
		return failure("KMSInvalidStateException", "The key has no usable current key material.")
	}
	return nil
}
