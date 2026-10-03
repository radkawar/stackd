package sqs

import (
	"bytes"
	"context"
	"errors"
	"slices"
	"time"

	"stackd/internal/awswire"
)

// A cache miss rolls the command back before KMS runs. The command then reads
// current state again; only key material is prepared, never a message mutation.
var errKeyPreparation = errors.New("SQS data key requires preparation")
var keyPending = &awswire.Error{Code: "InternalError", Message: "Data key preparation is pending.", StatusCode: 500}

type keySlot struct{ queueID, cacheID string }

type keyRequest struct {
	generate                    bool
	slot                        keySlot
	queueARN, keyID, ciphertext string
	expectedARN                 string
	reuse                       int
}

type keyResult struct {
	key cachedKey
	err *awswire.Error
}

// keyWork belongs to one authorized command. Failed KMS results are retained
// only for that command so batch entries can report their normal partial errors.
type keyWork struct {
	prepared  map[keyRequest]keyResult
	requested *keyRequest
	used      map[keySlot]cachedKey
	queues    map[queueKey]string
}

func (w *keyWork) close() {
	for _, result := range w.prepared {
		clear(result.key.plaintext)
	}
}

func (w *keyWork) pin(queues map[queueKey]*queue) {
	if w.queues == nil {
		w.queues = make(map[queueKey]string)
	}
	for name, q := range queues {
		w.queues[name] = q.id
	}
}

// publish runs after the successful state commit while the service lock is held.
// The cache owns its copy; request cleanup also erases unused prepared material.
func (w *keyWork) publish(runtimes map[string]*queueRuntime) {
	for slot, key := range w.used {
		key.plaintext = slices.Clone(key.plaintext)
		key.ciphertext = slices.Clone(key.ciphertext)
		runtimes[slot.queueID].keys[slot.cacheID] = key
	}
}

func (s *Service) dataKey(q *queue, request keyRequest) (cachedKey, *awswire.Error) {
	if s.kms == nil {
		return cachedKey{}, failure("KmsNotFound", "The KMS provider is unavailable.")
	}
	now := s.now()
	s.pruneKeys(q, now)
	if key, ok := q.keys[request.slot.cacheID]; ok {
		return key, nil
	}
	work := s.keyWork
	if result, ok := work.prepared[request]; ok {
		if result.err != nil {
			return cachedKey{}, result.err
		}
		if now.Before(result.key.expires) {
			work.used[request.slot] = result.key
			return result.key, nil
		}
		clear(result.key.plaintext)
		delete(work.prepared, request)
	}
	if work.requested == nil {
		work.requested = &request
	}
	return cachedKey{}, keyPending
}

func (s *Service) prepareDataKey(ctx context.Context, request keyRequest) keyResult {
	ctx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(s.lifetime, cancel)
	defer stop()
	defer cancel()
	ec := map[string]string{"aws:sqs:arn": request.queueARN}
	var key cachedKey
	if !request.generate {
		plaintext, arn, err := s.kms.Decrypt(ctx, []byte(request.ciphertext), ec)
		if err != nil {
			return keyResult{err: serviceError(err)}
		}
		if arn != request.expectedARN || len(plaintext) != 32 {
			clear(plaintext)
			return keyResult{err: failure("KmsInvalidState", "KMS returned an inconsistent data key.")}
		}
		key = cachedKey{plaintext: plaintext, arn: arn}
	} else {
		id := request.keyID
		if id == "alias/aws/sqs" {
			arn, err := s.kms.EnsureServiceKey(ctx, "sqs")
			if err != nil {
				return keyResult{err: serviceError(err)}
			}
			id = arn
		}
		plaintext, ciphertext, arn, err := s.kms.GenerateDataKey(ctx, id, ec)
		if err != nil {
			return keyResult{err: serviceError(err)}
		}
		check, _, err := s.kms.Decrypt(ctx, ciphertext, ec)
		if err != nil {
			clear(plaintext)
			return keyResult{err: serviceError(err)}
		}
		defer clear(check)
		if !bytes.Equal(plaintext, check) || len(plaintext) != 32 {
			clear(plaintext)
			return keyResult{err: failure("KmsInvalidState", "KMS returned an inconsistent data key.")}
		}
		key = cachedKey{plaintext: plaintext, ciphertext: ciphertext, arn: arn}
	}
	key.expires = s.clock.Now().Add(time.Duration(request.reuse) * time.Second)
	return keyResult{key: key}
}
