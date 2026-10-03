package rdsdata

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"time"

	engine "stackd/engine/rds"
	api "stackd/internal/awsapi/rdsdata"
	"stackd/internal/awsctx"
	"stackd/internal/scheduler"
)

const idleTimeout = 3 * time.Minute
const hardTimeout = 24 * time.Hour

type transaction struct {
	db                                                     *sql.DB
	tx                                                     *sql.Tx
	ctx                                                    context.Context
	cancel                                                 context.CancelFunc
	gate                                                   chan struct{}
	resource, secret, database, partition, account, region string
	endpoint                                               engine.Endpoint
	engine                                                 string
	// The service mutex protects deadlines/version/busy and map membership.
	hard, due time.Time
	version   uint64
	busy      bool
}

func (t *transaction) close(commit bool) error {
	var err error
	if commit {
		err = t.tx.Commit()
	} else {
		err = t.tx.Rollback()
		// A cancelled lease makes database/sql abort the native session. Its
		// competing rollback may report cancellation rather than ErrTxDone;
		// closing the pool below joins the connection retirement in either case.
		if errors.Is(err, sql.ErrTxDone) || t.ctx.Err() != nil && errors.Is(err, context.Canceled) {
			err = nil
		}
	}
	t.cancel()
	return errors.Join(err, t.db.Close())
}
func (s *Service) begin(ctx context.Context, in *api.BeginTransactionRequest) (*api.BeginTransactionResponse, error) {
	if value(in.Schema) != "" {
		return nil, failure("BadRequestException", "The schema parameter is not supported.")
	}
	t, err := s.resolve(ctx, "BeginTransaction", value(in.ResourceArn), value(in.SecretArn), value(in.Database))
	if err != nil {
		return nil, err
	}
	db, err := engine.Open(ctx, t.cluster.Engine, t.cluster.Endpoint, t.database, t.username, t.password)
	if err != nil {
		return nil, err
	}
	// A native transaction must outlive the BeginTransaction HTTP request.
	leaseCtx, cancel := context.WithCancel(s.lifetime)
	stop := context.AfterFunc(ctx, cancel)
	tx, err := db.BeginTx(leaseCtx, nil)
	stopped := stop()
	if err != nil || !stopped || ctx.Err() != nil {
		cancel()
		if tx != nil {
			_ = tx.Rollback()
		}
		_ = db.Close()
		if err == nil {
			err = ctx.Err()
		}
		return nil, err
	}
	var raw [32]byte
	if _, err = rand.Read(raw[:]); err != nil {
		_ = tx.Rollback()
		cancel()
		_ = db.Close()
		return nil, failure("InternalServerErrorException", "Unable to create transaction ID.", 500)
	}
	id := hex.EncodeToString(raw[:])
	now := s.clock.Now()
	m := awsctx.FromContext(ctx)
	lease := &transaction{db: db, tx: tx, ctx: leaseCtx, cancel: cancel, gate: make(chan struct{}, 1), resource: t.cluster.ARN, secret: t.secret, database: t.database, partition: m.Partition, account: m.AccountID, region: m.Region, endpoint: t.cluster.Endpoint, engine: t.cluster.Engine, hard: now.Add(hardTimeout), due: now.Add(idleTimeout), version: 1}
	lease.gate <- struct{}{}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		_ = lease.close(false)
		return nil, failure("ServiceUnavailableError", "The service is closed.", 503)
	}
	s.transactions[id] = lease
	s.mu.Unlock()
	s.jobs.Wake()
	return &api.BeginTransactionResponse{TransactionId: new(api.Id(id))}, nil
}
func transactionMissing() error {
	return failure("TransactionNotFoundException", "Transaction was not found, has expired, or does not match this resource, secret or database.", 404)
}
func (s *Service) acquire(ctx context.Context, id string, target target, checkDatabase bool) (*transaction, error) {
	m := awsctx.FromContext(ctx)
	s.mu.Lock()
	t := s.transactions[id]
	s.mu.Unlock()
	if t == nil {
		return nil, transactionMissing()
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-t.gate:
	}
	s.mu.Lock()
	valid := s.transactions[id] == t && t.resource == target.cluster.ARN && t.secret == target.secret && t.partition == m.Partition && t.account == m.AccountID && t.region == m.Region && t.endpoint == target.cluster.Endpoint && t.engine == target.cluster.Engine && (!checkDatabase || t.database == target.database)
	expired := !s.clock.Now().Before(t.due)
	if !valid || expired {
		if valid && expired {
			delete(s.transactions, id)
		}
		s.mu.Unlock()
		if valid && expired {
			_ = t.close(false)
		}
		t.gate <- struct{}{}
		return nil, transactionMissing()
	}
	t.busy = true
	t.due = t.hard
	t.version++
	s.mu.Unlock()
	s.jobs.Wake()
	return t, nil
}
func (s *Service) release(id string, t *transaction) {
	s.mu.Lock()
	if s.transactions[id] == t {
		t.busy = false
		t.due = s.clock.Now().Add(idleTimeout)
		if t.hard.Before(t.due) {
			t.due = t.hard
		}
		t.version++
	}
	s.mu.Unlock()
	t.gate <- struct{}{}
	s.jobs.Wake()
}
func (s *Service) finish(ctx context.Context, action, resource, secret, id string, commit bool) error {
	target, err := s.resolve(ctx, action, resource, secret, "")
	if err != nil {
		return err
	}
	t, err := s.acquire(ctx, id, target, false)
	if err != nil {
		return err
	}
	s.mu.Lock()
	delete(s.transactions, id)
	s.mu.Unlock()
	err = t.close(commit)
	t.gate <- struct{}{}
	s.jobs.Wake()
	return err
}
func (s *Service) commit(ctx context.Context, in *api.CommitTransactionRequest) (*api.CommitTransactionResponse, error) {
	if err := s.finish(ctx, "CommitTransaction", value(in.ResourceArn), value(in.SecretArn), value(in.TransactionId), true); err != nil {
		return nil, err
	}
	return &api.CommitTransactionResponse{TransactionStatus: new(api.TransactionStatus("Transaction Committed"))}, nil
}
func (s *Service) rollback(ctx context.Context, in *api.RollbackTransactionRequest) (*api.RollbackTransactionResponse, error) {
	if err := s.finish(ctx, "RollbackTransaction", value(in.ResourceArn), value(in.SecretArn), value(in.TransactionId), false); err != nil {
		return nil, err
	}
	return &api.RollbackTransactionResponse{TransactionStatus: new(api.TransactionStatus("Transaction Rolled Back"))}, nil
}

type transactionJobs struct{ service *Service }

func (j transactionJobs) Next(ctx context.Context) (scheduler.Job, bool, error) {
	if err := ctx.Err(); err != nil {
		return scheduler.Job{}, false, err
	}
	s := j.service
	s.mu.Lock()
	defer s.mu.Unlock()
	var next scheduler.Job
	found := false
	for id, t := range s.transactions {
		job := scheduler.Job{Key: id, Version: t.version, Due: t.due}
		if !found || scheduler.Compare(job, next) < 0 {
			next = job
			found = true
		}
	}
	return next, found, nil
}
func (j transactionJobs) Run(ctx context.Context, job scheduler.Job) error {
	s := j.service
	s.mu.Lock()
	t := s.transactions[job.Key]
	if t == nil || t.version != job.Version || t.due.After(s.clock.Now()) {
		s.mu.Unlock()
		return nil
	}
	// Remove before waiting for any native operation. Idle sessions roll back
	// normally; a hard-expired busy session must first interrupt native I/O.
	delete(s.transactions, job.Key)
	if t.busy {
		t.cancel()
	}
	s.mu.Unlock()
	// Cancellation makes the native operation release this gate. The source must
	// finish closing the session even when the shared driver is shutting down.
	<-t.gate
	err := t.close(false)
	t.gate <- struct{}{}
	return err
}
