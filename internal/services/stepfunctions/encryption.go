package stepfunctions

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sync"
	"time"

	"stackd/clock"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
)

type workflowKeySlot struct {
	machine, resource, role, key string
}

type workflowDataKey struct {
	cipher  cipher.AEAD
	wrapped []byte
	expires time.Time
}

// workflowEncryption owns only disposable key material. Wrapped keys and
// ciphertext belong to resource records and survive an instance restart.
type workflowEncryption struct {
	keys        EncryptionKeys
	clock       clock.Clock
	mu          sync.Mutex
	write       map[workflowKeySlot]workflowDataKey
	definitions map[[32]byte]workflowDataKey
	synchronous map[ExecutionKey]workflowDataKey
}

func (e *workflowEncryption) close() {
	e.mu.Lock()
	clear(e.write)
	clear(e.definitions)
	clear(e.synchronous)
	e.mu.Unlock()
}

func workflowCipher(plain []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(plain)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func workflowKeyContext(ctx context.Context, revision RevisionRecord, role string) context.Context {
	if role == "" {
		return ctx
	}
	metadata := awsctx.FromContext(ctx)
	metadata.Partition, metadata.AccountID, metadata.Region = revision.Key.Partition, revision.Key.AccountID, revision.Key.Region
	ctx = awsctx.WithMetadata(ctx, metadata)
	return awsctx.WithServicePrincipal(ctx, awsctx.ServicePrincipal{Name: "states.amazonaws.com", SourceARN: revision.Machine.ARN(), Type: "AWSService"})
}

func (e *workflowEncryption) generate(ctx context.Context, revision RevisionRecord, resource, role string, config EncryptionConfig) (workflowDataKey, error) {
	if e.keys == nil {
		return workflowDataKey{}, errors.New("step functions encryption keys are not configured")
	}
	now := e.clock.Now()
	slot := workflowKeySlot{machine: revision.MachineID, resource: resource, role: role, key: config.KMSKeyARN}
	// The configured reuse period applies to service execution, not permission
	// checks for unrelated API callers creating or reading definitions.
	if role != "" {
		e.mu.Lock()
		material, ok := e.write[slot]
		e.mu.Unlock()
		if ok && now.Before(material.expires) {
			return material, nil
		}
	}
	ctx = workflowKeyContext(ctx, revision, role)
	plain, wrapped, _, rejected := e.keys.GenerateDataKey(ctx, resource, role, config.KMSKeyARN)
	if rejected != nil {
		return workflowDataKey{}, rejected
	}
	defer clear(plain)
	aead, err := workflowCipher(plain)
	if err != nil {
		return workflowDataKey{}, err
	}
	material := workflowDataKey{cipher: aead, wrapped: wrapped, expires: now.Add(time.Duration(config.DataKeyReuseSeconds) * time.Second)}
	if role != "" {
		e.mu.Lock()
		if e.write == nil {
			e.write = make(map[workflowKeySlot]workflowDataKey)
		}
		for key, previous := range e.write {
			if !now.Before(previous.expires) {
				delete(e.write, key)
			}
		}
		e.write[slot] = material
		e.mu.Unlock()
	}
	return material, nil
}

func (e *workflowEncryption) decrypt(ctx context.Context, revision RevisionRecord, resource, role string, wrapped []byte) (cipher.AEAD, error) {
	if e.keys == nil {
		return nil, errors.New("step functions encryption keys are not configured")
	}
	ctx = workflowKeyContext(ctx, revision, role)
	plain, _, rejected := e.keys.Decrypt(ctx, resource, role, wrapped)
	if rejected != nil {
		return nil, rejected
	}
	aead, err := workflowCipher(plain)
	clear(plain)
	if err != nil {
		return nil, err
	}
	return aead, nil
}

func sealWorkflowPayload(material workflowDataKey, plain []byte) *EncryptedPayload {
	nonce := make([]byte, material.cipher.NonceSize(), material.cipher.NonceSize()+len(plain)+material.cipher.Overhead())
	_, _ = rand.Read(nonce)
	return &EncryptedPayload{DataKey: material.wrapped, Content: material.cipher.Seal(nonce, nonce, plain, nil)}
}

func openWorkflowPayload(aead cipher.AEAD, payload *EncryptedPayload) ([]byte, error) {
	n := aead.NonceSize()
	if len(payload.Content) < n {
		return nil, errors.New("invalid encrypted Step Functions payload")
	}
	return aead.Open(nil, payload.Content[:n], payload.Content[n:], nil)
}

// payloadReader unwraps each distinct key once within an authorized operation.
// It does not reuse a caller's Decrypt permission in another request.
type payloadReader struct {
	service  *Service
	reader   Reader
	revision RevisionRecord
	role     string
	ciphers  map[[32]byte]cipher.AEAD
	fixed    *workflowDataKey
}

func (r *payloadReader) open(resource string, payload *EncryptedPayload) ([]byte, error) {
	id := sha256.Sum256(payload.DataKey)
	aead := r.ciphers[id]
	if r.fixed != nil && sha256.Sum256(r.fixed.wrapped) == id {
		aead = r.fixed.cipher
	}
	if aead == nil {
		var err error
		aead, err = r.service.encryption.decrypt(r.reader.Context(), r.revision, resource, r.role, payload.DataKey)
		if err != nil {
			return nil, err
		}
		if r.ciphers == nil {
			r.ciphers = make(map[[32]byte]cipher.AEAD)
		}
		r.ciphers[id] = aead
	}
	return openWorkflowPayload(aead, payload)
}

func (r *payloadReader) decode(resource string, payload *EncryptedPayload, value any) error {
	plain, err := r.open(resource, payload)
	if err != nil {
		return err
	}
	return json.Unmarshal(plain, value)
}

func (s *Service) openRevision(r Reader, revision RevisionRecord, role string) (RevisionRecord, error) {
	if revision.Encrypted == nil {
		return revision, nil
	}
	reader := payloadReader{service: s, reader: r, revision: revision, role: role}
	plain, err := reader.open(revision.Machine.ARN(), revision.Encrypted)
	if err != nil {
		return RevisionRecord{}, err
	}
	revision.Definition = string(plain)
	return revision, nil
}

func (s *Service) sealRevision(ctx context.Context, revision RevisionRecord, role string) (RevisionRecord, error) {
	if revision.KMSKeyARN == "" {
		revision.Encrypted = nil
		revision.DefinitionIdentity = ""
		return revision, nil
	}
	material, err := s.encryption.generate(ctx, revision, revision.Machine.ARN(), role, revision.EncryptionConfig)
	if err != nil {
		return RevisionRecord{}, err
	}
	revision.DefinitionIdentity = definitionIdentity(revision.Definition)
	revision.Encrypted = sealWorkflowPayload(material, []byte(revision.Definition))
	s.encryption.mu.Lock()
	if s.encryption.definitions == nil {
		s.encryption.definitions = make(map[[32]byte]workflowDataKey)
	}
	now := s.clock.Now()
	for key, previous := range s.encryption.definitions {
		if !now.Before(previous.expires) {
			delete(s.encryption.definitions, key)
		}
	}
	s.encryption.definitions[sha256.Sum256(material.wrapped)] = material
	s.encryption.mu.Unlock()
	revision.Definition = ""
	return revision, nil
}

func definitionIdentity(source string) string {
	sum := sha256.Sum256([]byte(source))
	return hex.EncodeToString(sum[:])
}

func sameDefinition(revision RevisionRecord, source string) bool {
	if revision.Encrypted == nil {
		return revision.Definition == source
	}
	return revision.DefinitionIdentity == definitionIdentity(source)
}

func encryptionAdmissionError(err error) error {
	var rejected *awswire.Error
	if errors.As(err, &rejected) && rejected.Code == "KmsInvalidStateException" {
		return failure("InvalidEncryptionConfiguration", "Invalid Encryption Configuration: "+rejected.Message, 400)
	}
	return err
}
