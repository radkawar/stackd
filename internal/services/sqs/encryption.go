package sqs

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"time"

	"stackd/internal/awswire"
)

type sealedPayload struct {
	data      []byte
	encrypted bool
	keyARN    string
	dataKey   []byte
}
type cachedKey struct {
	plaintext, ciphertext []byte
	arn                   string
	expires               time.Time
}

func (s *Service) seal(ctx context.Context, q *queue, p payload) (sealedPayload, *awswire.Error) {
	data, err := json.Marshal(p)
	if err != nil {
		return sealedPayload{}, failure("InvalidParameterValue", "Unable to encode message.")
	}
	if !q.config.managedSSE && q.config.kmsKey == "" {
		return sealedPayload{data: data}, nil
	}
	aead := q.cipher
	out := sealedPayload{encrypted: true}
	if q.config.kmsKey != "" {
		key, err := s.producerKey(ctx, q)
		if err != nil {
			return sealedPayload{}, err
		}
		block, cipherErr := aes.NewCipher(key.plaintext)
		if cipherErr != nil {
			return sealedPayload{}, failure("KmsInvalidState", "KMS returned an invalid data key.")
		}
		aead, _ = cipher.NewGCM(block)
		out.keyARN = key.arn
		out.dataKey = key.ciphertext
	}
	nonce := make([]byte, aead.NonceSize())
	_, _ = rand.Read(nonce)
	out.data = aead.Seal(nonce, nonce, data, []byte(q.id))
	return out, nil
}
func (s *Service) open(ctx context.Context, q *queue, m *message) (payload, *awswire.Error) {
	data := m.data
	if m.encrypted {
		aead := q.cipher
		if m.keyARN != "" {
			key, err := s.consumerKey(ctx, q, m)
			if err != nil {
				return payload{}, err
			}
			block, cipherErr := aes.NewCipher(key)
			if cipherErr != nil {
				return payload{}, failure("KmsInvalidState", "KMS returned an invalid data key.")
			}
			aead, _ = cipher.NewGCM(block)
		}
		n := aead.NonceSize()
		if len(data) < n {
			return payload{}, failure("KmsInvalidState", "Invalid encrypted message.")
		}
		var err error
		data, err = aead.Open(nil, data[:n], data[n:], []byte(q.id))
		if err != nil {
			return payload{}, failure("KmsInvalidState", "Unable to decrypt encrypted message.")
		}
	}
	var p payload
	if err := json.Unmarshal(data, &p); err != nil {
		return payload{}, &awswire.Error{Code: "InternalError", Message: "Invalid stored message.", StatusCode: 500}
	}
	return p, nil
}
func (s *Service) producerKey(ctx context.Context, q *queue) (cachedKey, *awswire.Error) {
	return s.dataKey(q, keyRequest{slot: keySlot{q.id, "send:" + keyRequester(ctx) + ":" + q.config.kmsKey}, queueARN: q.key.arn(), keyID: q.config.kmsKey, generate: true, reuse: q.config.kmsReuse})
}
func (s *Service) consumerKey(ctx context.Context, q *queue, m *message) ([]byte, *awswire.Error) {
	digest := sha256.Sum256(m.dataKey)
	key, err := s.dataKey(q, keyRequest{slot: keySlot{q.id, "receive:" + keyRequester(ctx) + ":" + hex.EncodeToString(digest[:])}, queueARN: q.key.arn(), ciphertext: string(m.dataKey), expectedARN: m.keyARN, reuse: q.config.kmsReuse})
	return key.plaintext, err
}
func (s *Service) pruneKeys(q *queue, now time.Time) {
	for id, key := range q.keys {
		if !now.Before(key.expires) {
			clear(key.plaintext)
			delete(q.keys, id)
		}
	}
}
