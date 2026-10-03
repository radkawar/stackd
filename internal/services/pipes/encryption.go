package pipes

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"slices"
	api "stackd/internal/awsapi/pipes"
)

type sensitiveConfiguration struct {
	Filters            []string           `json:"filters"`
	EnrichmentTemplate string             `json:"enrichmentTemplate"`
	TargetTemplate     *api.InputTemplate `json:"targetTemplate"`
}

func (s *Service) seal(ctx context.Context, p *PipeRecord, key *api.KmsKeyIdentifier) error {
	if key != nil {
		p.KMSKeyARN = value(key)
	}
	if p.KMSKeyARN == "" {
		p.Encrypted = nil
		return nil
	}
	if s.keys == nil {
		return unsupported("Customer-managed Pipes encryption requires a configured KMS adapter.")
	}
	plain, wrapped, keyARN, rejected := s.keys.Generate(ctx, *p, p.KMSKeyARN)
	if rejected != nil {
		return rejected
	}
	defer clear(plain)
	block, e := aes.NewCipher(plain)
	if e != nil {
		return e
	}
	aead, e := cipher.NewGCM(block)
	if e != nil {
		return e
	}
	payload, e := json.Marshal(sensitiveConfiguration{p.Source.Filters, p.EnrichmentTemplate, p.Target.InputTemplate})
	if e != nil {
		return e
	}
	defer clear(payload)
	nonce := make([]byte, aead.NonceSize())
	if _, e = rand.Read(nonce); e != nil {
		return e
	}
	p.KMSKeyARN = keyARN
	p.Encrypted = &EncryptedConfiguration{WrappedKey: wrapped, Nonce: nonce, Ciphertext: aead.Seal(nil, nonce, payload, []byte(p.Key.ARN()))}
	return nil
}

func (s *Service) open(ctx context.Context, p PipeRecord) (PipeRecord, error) {
	if p.Encrypted == nil {
		return p, nil
	}
	if s.keys == nil {
		return p, unsupported("Customer-managed Pipes encryption requires a configured KMS adapter.")
	}
	key, rejected := s.keys.Decrypt(ctx, p, p.Encrypted.WrappedKey)
	if rejected != nil {
		return p, rejected
	}
	defer clear(key)
	block, e := aes.NewCipher(key)
	if e != nil {
		return p, e
	}
	aead, e := cipher.NewGCM(block)
	if e != nil {
		return p, e
	}
	if len(p.Encrypted.Nonce) != aead.NonceSize() {
		return p, invalid("Invalid encrypted pipe configuration.")
	}
	raw, e := aead.Open(nil, p.Encrypted.Nonce, p.Encrypted.Ciphertext, []byte(p.Key.ARN()))
	if e != nil {
		return p, e
	}
	defer clear(raw)
	var configuration sensitiveConfiguration
	if e = json.Unmarshal(raw, &configuration); e != nil {
		return p, e
	}
	p.Source.Filters = configuration.Filters
	p.EnrichmentTemplate = configuration.EnrichmentTemplate
	p.Target.InputTemplate = configuration.TargetTemplate
	return p, nil
}

// Stored removes cleartext sensitive fields from a row with an authenticated
// envelope. Repositories call this at the ownership boundary, so ordinary state
// transitions cannot accidentally persist a worker's decrypted working copy.
func Stored(p PipeRecord) PipeRecord {
	if p.Encrypted != nil {
		p.Source.Filters = nil
		p.EnrichmentTemplate = ""
		p.Target.InputTemplate = nil
	}
	return p
}
func cloneEncrypted(v *EncryptedConfiguration) *EncryptedConfiguration {
	if v == nil {
		return nil
	}
	return &EncryptedConfiguration{WrappedKey: slices.Clone(v.WrappedKey), Nonce: slices.Clone(v.Nonce), Ciphertext: slices.Clone(v.Ciphertext)}
}
