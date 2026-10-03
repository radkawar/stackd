package sqs

import (
	"context"
	"errors"
	"net/http"
	"time"

	"stackd/internal/authorization"
	"stackd/internal/awswire"
)

// NewWithRepository selects storage without changing queue semantics or the
// authorization/KMS boundaries. Repository callbacks own resource transactions;
// channels, worker cancellation and plaintext key caches stay process-local.
func NewWithRepository(repository Repository, kms KMS, authorizer authorization.Authorizer) *Service {
	return NewWithConfig(Config{Repository: repository, KMS: kms, Authorizer: authorizer})
}
func (s *Service) prepare(reader Reader) error {
	s.transactionTime = s.clock.Now()
	s.reader = reader
	s.queues = make(map[queueKey]*queue)
	s.deleted = make(map[queueKey]time.Time)
	s.removed = make(map[queueKey]bool)
	s.stateErr = nil
	records, err := reader.MoveTasks()
	if err != nil {
		return err
	}
	s.tasks = make(map[string]*MoveTaskRecord, len(records))
	s.nextMove = 0
	s.jobsChanged = false
	for _, record := range records {
		s.tasks[record.Handle] = &record
		if record.Sequence > s.nextMove {
			s.nextMove = record.Sequence
		}
	}
	return nil
}
func (s *Service) lookupQueue(key queueKey) *queue {
	if s.removed[key] {
		return nil
	}
	if q, ok := s.queues[key]; ok {
		return q
	}
	record, err := s.reader.Queue(publicKey(key))
	if errors.Is(err, ErrNotFound) {
		return nil
	}
	if err != nil {
		s.stateErr = err
		return nil
	}
	q, err := s.queueFromRecord(record)
	if err != nil {
		s.stateErr = err
		return nil
	}
	if s.keyWork != nil {
		if original, ok := s.keyWork.queues[key]; ok && original != q.id {
			s.stateErr = failure("QueueDoesNotExist", "The queue was replaced while preparing message encryption.")
			return nil
		}
	}
	s.queues[key] = q
	return q
}
func (s *Service) loadMessages(q *queue) {
	if q.messagesLoaded {
		return
	}
	records, err := s.reader.Messages(q.id)
	if err != nil {
		s.stateErr = err
		return
	}
	hydrateMessages(q, records)
}
func (s *Service) allQueues() map[queueKey]*queue {
	records, err := s.reader.Queues()
	if err != nil {
		s.stateErr = err
		return nil
	}
	for _, record := range records {
		key := privateKey(record.Key)
		if s.removed[key] || s.queues[key] != nil {
			continue
		}
		q, err := s.queueFromRecord(record)
		if err != nil {
			s.stateErr = err
			continue
		}
		s.queues[key] = q
	}
	return s.queues
}
func (s *Service) deletedAt(key queueKey) time.Time {
	if at, ok := s.deleted[key]; ok {
		return at
	}
	at, err := s.reader.DeletedAt(publicKey(key))
	if err != nil {
		s.stateErr = err
	}
	return at
}
func (s *Service) flush(tx Transaction) error {
	if s.stateErr != nil {
		return s.stateErr
	}
	for key, q := range s.queues {
		if s.removed[key] {
			continue
		}
		if err := tx.PutQueue(queueRecord(q)); err != nil {
			return err
		}
		if q.messagesLoaded {
			q.updateFairness(s.now())
			if err := tx.PutMessages(q.id, queueMessages(q)); err != nil {
				return err
			}
		}
	}
	for key := range s.removed {
		if err := tx.DeleteQueue(publicKey(key)); err != nil {
			return err
		}
	}
	for key, at := range s.deleted {
		if err := tx.SetDeletedAt(publicKey(key), at); err != nil {
			return err
		}
	}
	for _, task := range s.tasks {
		if err := tx.PutMoveTask(*task); err != nil {
			return err
		}
	}
	return nil
}
func storageError(err error) *awswire.Error {
	var wire *awswire.Error
	if errors.As(err, &wire) {
		return wire
	}
	return &awswire.Error{Code: "InternalError", Message: "The SQS storage transaction failed.", StatusCode: 500}
}

// authorizedUpdate evaluates current IAM, Organizations and queue policies in
// the resource transaction before acting. A data-key miss aborts the callback,
// prepares key material outside both locks, and repeats authorization and the
// command against current state.
func (s *Service) authorizedUpdate(r *http.Request, action string, input any, audit *commandAudit, fn func(*http.Request) *awswire.Error) *awswire.Error {
	return s.authorizedCommand(r.Context(), audit, func(ctx context.Context) ([]authorization.Request, *awswire.Error) {
		return s.permissions(r.WithContext(ctx), action, input)
	}, func(ctx context.Context) *awswire.Error { return fn(r.WithContext(ctx)) })
}

// authorizedCommand owns queue authorization, key preparation and atomic state
// publication for both protocol requests and internal service delivery. Each
// attempt isolates rejection from a caller's transaction; successful writes and
// their audit remain part of that transaction.
func (s *Service) authorizedCommand(ctx context.Context, audit *commandAudit, permissions func(context.Context) ([]authorization.Request, *awswire.Error), fn func(context.Context) *awswire.Error) *awswire.Error {
	work := keyWork{prepared: make(map[keyRequest]keyResult)}
	defer work.close()
	for {
		s.mu.Lock()
		if s.closed {
			s.mu.Unlock()
			return &awswire.Error{Code: "ServiceUnavailable", Message: "The SQS service is shutting down.", StatusCode: 503}
		}
		s.keyWork = &work
		work.requested = nil
		work.used = make(map[keySlot]cachedKey)
		err := s.repository.Attempt(ctx, func(tx Transaction) error {
			ctx := tx.Context()
			if err := s.prepare(tx); err != nil {
				return err
			}
			s.command = audit
			if audit != nil {
				audit.sendSizes = audit.sendSizes[:0]
				audit.deduplicated = 0
				audit.failedBatchSizes = false
			}
			permissions, err := permissions(ctx)
			if s.stateErr != nil {
				return s.stateErr
			}
			if err != nil {
				return err
			}
			instant := s.now()
			if audit != nil && audit.resourceARN == "" && len(permissions) != 0 {
				if _, valid := parseQueueARN(permissions[0].ResourceARN); valid {
					audit.resourceARN = permissions[0].ResourceARN
				}
			}
			for _, permission := range permissions {
				permission.EvaluationTime = &instant
				if err := s.authorizer.Authorize(ctx, permission); err != nil {
					return err
				}
			}
			operationErr := fn(ctx)
			if s.stateErr != nil {
				return s.stateErr
			}
			if work.requested != nil {
				return errKeyPreparation
			}
			if operationErr != nil {
				return operationErr
			}
			if audit != nil && audit.final {
				if err := s.stageCommandMetrics(tx, audit); err != nil {
					return err
				}
			}
			// API completion consumers (Config, Tagging) read the owner's typed
			// repository in this same transaction, so staged queue state must be
			// visible before the successful completion is recorded.
			if err := s.flush(tx); err != nil {
				return err
			}
			if audit != nil && audit.final {
				return s.recordAPI(ctx, audit, nil, s.now())
			}
			return nil
		})
		s.reader = nil
		s.command = nil
		s.keyWork = nil
		preparing := errors.Is(err, errKeyPreparation)
		if preparing {
			work.pin(s.queues)
			s.effects.Add(1)
		}
		if err == nil {
			work.publish(s.runtimes)
		}
		wake := err == nil && s.jobsChanged
		s.mu.Unlock()
		if preparing {
			request := *work.requested
			result := s.prepareDataKey(ctx, request)
			s.effects.Done()
			work.prepared[request] = result
			continue
		}
		if wake {
			s.jobs.Wake()
		}
		if err != nil {
			return storageError(err)
		}
		return nil
	}
}
func (s *Service) updateState(ctx context.Context, fn func()) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	err := s.repository.Update(ctx, func(tx Transaction) error {
		if err := s.prepare(tx); err != nil {
			return err
		}
		fn()
		return s.flush(tx)
	})
	s.reader = nil
	return err
}
