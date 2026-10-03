package stepfunctions

import (
	"crypto/sha256"
	"time"
)

// Synchronous Express does not acquire an execution-history data key through
// the execution role. Its caller needs Decrypt only when returning protected
// data. The in-flight evaluator retains the admitted key while the HTTP caller
// waits, independently of the execution role's permissions for task effects.
func (s *Service) synchronousMaterial(r Reader, revision RevisionRecord, metadataOnly bool) (*workflowDataKey, error) {
	if revision.Encrypted == nil {
		return nil, nil
	}
	now := s.clock.Now()
	if metadataOnly {
		s.encryption.mu.Lock()
		material, ok := s.encryption.definitions[sha256.Sum256(revision.Encrypted.DataKey)]
		s.encryption.mu.Unlock()
		if ok && now.Before(material.expires) {
			return &material, nil
		}
	}
	role := ""
	if metadataOnly {
		role = revision.RoleARN
	}
	aead, err := s.encryption.decrypt(r.Context(), revision, revision.Machine.ARN(), role, revision.Encrypted.DataKey)
	if err != nil {
		return nil, err
	}
	return &workflowDataKey{cipher: aead, wrapped: revision.Encrypted.DataKey, expires: now.Add(5 * time.Minute)}, nil
}

func (e *workflowEncryption) retainSynchronous(key ExecutionKey, material workflowDataKey, deadline time.Time) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.synchronous == nil {
		e.synchronous = make(map[ExecutionKey]workflowDataKey)
	}
	now := e.clock.Now()
	for key, previous := range e.synchronous {
		if now.After(previous.expires) {
			delete(e.synchronous, key)
		}
	}
	material.expires = deadline
	e.synchronous[key] = material
}

func (e *workflowEncryption) synchronousMaterial(key ExecutionKey) *workflowDataKey {
	e.mu.Lock()
	defer e.mu.Unlock()
	material, ok := e.synchronous[key]
	if !ok {
		return nil
	}
	return &material
}

func (e *workflowEncryption) releaseSynchronous(key ExecutionKey) {
	e.mu.Lock()
	delete(e.synchronous, key)
	e.mu.Unlock()
}
