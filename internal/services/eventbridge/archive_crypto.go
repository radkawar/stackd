package eventbridge

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"

	"stackd/internal/awswire"
)

// ArchiveKeys separates archive state from caller/service KMS authorization.
// PrepareKey performs the configured-key admission calls; GenerateDataKey and
// DecryptDataKey run as EventBridge for retained event processing. Implementations
// must make these calls outside the EventBridge repository transaction.
type ArchiveKeys interface {
	ResolveKey(context.Context, BusKey, string) (string, *awswire.Error)
	PrepareKey(context.Context, BusKey, string) ([]byte, []byte, *awswire.Error)
	DescribeKey(context.Context, BusKey, string) *awswire.Error
	GenerateDataKey(ctx context.Context, source BusKey, keyARN, ruleARN string) ([]byte, []byte, *awswire.Error)
	DecryptDataKey(ctx context.Context, source BusKey, wrapped []byte, ruleARN, keyARN string) ([]byte, *awswire.Error)
	// ReEncryptDataKey returns a wrapped key for a customer destination, or the
	// unwrapped key when returning to service-owned storage (empty destination).
	ReEncryptDataKey(ctx context.Context, source BusKey, wrapped []byte, destination, ruleARN string) ([]byte, *awswire.Error)
}

func (s *Service) resolveArchiveKey(ctx context.Context, source BusKey, identifier string) (string, *awswire.Error) {
	if identifier == "" {
		return "", nil
	}
	if s.keys == nil {
		return "", unsupported("No archive KMS provider is configured.")
	}
	return s.keys.ResolveKey(ctx, source, identifier)
}

func (s *Service) prepareArchivePayload(ctx context.Context, source BusKey, keyARN string, content []byte) (ArchivePayload, *awswire.Error) {
	if keyARN == "" {
		return ArchivePayload{Content: content}, nil
	}
	plaintext, wrapped, rejected := s.keys.PrepareKey(ctx, source, keyARN)
	if rejected != nil {
		return ArchivePayload{}, rejected
	}
	return sealArchiveData(content, plaintext, wrapped)
}

func (s *Service) describeArchiveKey(ctx context.Context, source BusKey, keyARN string) *awswire.Error {
	if keyARN == "" {
		return nil
	}
	return s.keys.DescribeKey(ctx, source, keyARN)
}

func (s *Service) encryptArchivePayload(ctx context.Context, archive ArchiveRecord, content []byte, ruleARN string) (ArchivePayload, *awswire.Error) {
	if archive.KeyARN == "" {
		return ArchivePayload{Content: content}, nil
	}
	if s.keys == nil {
		return ArchivePayload{}, unsupported("No archive KMS provider is configured.")
	}
	plaintext, wrapped, rejected := s.keys.GenerateDataKey(ctx, archive.Source, archive.KeyARN, ruleARN)
	if rejected != nil {
		return ArchivePayload{}, rejected
	}
	return sealArchiveData(content, plaintext, wrapped)
}

func sealArchiveData(content, plaintext, wrapped []byte) (ArchivePayload, *awswire.Error) {
	defer clear(plaintext)
	aead, err := archiveCipher(plaintext)
	if err != nil {
		return ArchivePayload{}, failure("InternalException", "Unable to initialize archive encryption.", 500)
	}
	return ArchivePayload{Content: sealEnvelope(aead, content), DataKey: wrapped}, nil
}

func (s *Service) openArchivePayload(ctx context.Context, source BusKey, payload ArchivePayload, ruleARN, keyARN string) ([]byte, *awswire.Error) {
	if len(payload.DataKey) == 0 {
		return payload.Content, nil
	}
	if s.keys == nil {
		return nil, unsupported("No archive KMS provider is configured.")
	}
	plaintext, rejected := s.keys.DecryptDataKey(ctx, source, payload.DataKey, ruleARN, keyARN)
	if rejected != nil {
		return nil, rejected
	}
	defer clear(plaintext)
	aead, err := archiveCipher(plaintext)
	if err != nil {
		return nil, failure("InternalException", "Unable to initialize archive decryption.", 500)
	}
	content, rejected := openEnvelope(aead, payload.Content)
	if rejected != nil {
		return nil, rejected
	}
	return content, nil
}

func (s *Service) migrateArchivePayload(ctx context.Context, archive ArchiveRecord, entry ArchiveEntry) (ArchivePayload, *awswire.Error) {
	payload := entry.Payload
	if len(payload.DataKey) == 0 {
		return s.encryptArchivePayload(ctx, archive, payload.Content, "")
	}
	if s.keys == nil {
		return ArchivePayload{}, unsupported("No archive KMS provider is configured.")
	}
	key, rejected := s.keys.ReEncryptDataKey(ctx, archive.Source, payload.DataKey, archive.KeyARN, archiveEntryRuleARN(archive, entry))
	if rejected != nil {
		return ArchivePayload{}, rejected
	}
	if archive.KeyARN != "" {
		// Rewrap only the data key: the authenticated event is unchanged.
		return ArchivePayload{Content: payload.Content, DataKey: key}, nil
	}
	defer clear(key)
	aead, err := archiveCipher(key)
	if err != nil {
		return ArchivePayload{}, failure("InternalException", "Unable to initialize archive decryption.", 500)
	}
	content, rejected := openEnvelope(aead, payload.Content)
	if rejected != nil {
		return ArchivePayload{}, rejected
	}
	return ArchivePayload{Content: content}, nil
}

func archiveEntryRuleARN(archive ArchiveRecord, entry ArchiveEntry) string {
	if entry.RuleContext {
		return archiveRuleKey(archive).ARN()
	}
	return ""
}

func archiveCipher(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// The same authenticated envelope protects archive and bus payloads. KMS
// authority and encryption contexts belong to their respective consumers.
func sealEnvelope(aead cipher.AEAD, content []byte) []byte {
	nonce := make([]byte, aead.NonceSize(), aead.NonceSize()+len(content)+aead.Overhead())
	_, _ = rand.Read(nonce)
	return aead.Seal(nonce, nonce, content, nil)
}

func openEnvelope(aead cipher.AEAD, content []byte) ([]byte, *awswire.Error) {
	n := aead.NonceSize()
	if len(content) < n {
		return nil, failure("InternalException", "Invalid encrypted event payload.", 500)
	}
	plaintext, err := aead.Open(nil, content[:n], content[n:], nil)
	if err != nil {
		return nil, failure("InternalException", "Unable to decrypt event payload.", 500)
	}
	return plaintext, nil
}
