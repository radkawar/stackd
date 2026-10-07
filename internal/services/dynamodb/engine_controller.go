package dynamodb

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"

	"stackd/clock"
	engine "stackd/engine/dynamodb"
)

// engineController reconciles retained control intents without holding kernel
// transactions across native process or data-plane calls.
type engineController struct {
	service         *Service
	ctx             context.Context
	cancel          context.CancelFunc
	mu              sync.Mutex
	started, closed bool
	wakeups         chan struct{}
	databases       map[string]engine.Database
	dataGates       map[string]chan struct{}
	work            sync.WaitGroup
}

func newEngineController(s *Service) *engineController {
	ctx, cancel := context.WithCancel(context.Background())
	return &engineController{service: s, ctx: ctx, cancel: cancel, wakeups: make(chan struct{}, 1), databases: map[string]engine.Database{}, dataGates: map[string]chan struct{}{}}
}
func (s *Service) Start() error {
	if err := s.engines.start(); err != nil {
		return err
	}
	s.jobs.Start()
	return nil
}
func (s *Service) Close() error {
	s.jobs.Close()
	return s.engines.close()
}
func (c *engineController) wake() {
	select {
	case c.wakeups <- struct{}{}:
	default:
	}
}
func (c *engineController) start() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return errors.New("DynamoDB service is closed")
	}
	if c.started || c.service.runtime == nil {
		return nil
	}
	c.started = true
	c.work.Add(1)
	go c.run()
	return nil
}
func (c *engineController) database(ctx context.Context, spec engine.Specification) (engine.Database, error) {
	ctx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(c.ctx, cancel)
	defer stop()
	defer cancel()
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil, errors.New("DynamoDB service is closed")
	}
	if db, ok := c.databases[spec.ID]; ok {
		c.mu.Unlock()
		return db, nil
	}
	c.mu.Unlock()
	if c.service.runtime == nil {
		return nil, engineUnavailable()
	}
	db, err := c.service.runtime.Open(ctx, spec)
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		_ = db.Close()
		return nil, errors.New("DynamoDB service is closed")
	}
	if existing, ok := c.databases[spec.ID]; ok {
		c.mu.Unlock()
		_ = db.Close()
		return existing, nil
	}
	c.databases[spec.ID] = db
	c.mu.Unlock()
	return db, nil
}

// lockData serializes native write/capture intervals, including TTL and recovery.
// No repository transaction is held while waiting for this database gate.
func (c *engineController) lockData(ctx context.Context, id string) (func(), error) {
	c.mu.Lock()
	gate := c.dataGates[id]
	if gate == nil {
		gate = make(chan struct{}, 1)
		gate <- struct{}{}
		c.dataGates[id] = gate
	}
	c.mu.Unlock()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-c.ctx.Done():
		return nil, c.ctx.Err()
	case <-gate:
		return func() { gate <- struct{}{} }, nil
	}
}
func (c *engineController) run() {
	defer c.work.Done()
	for {
		retry := false
		var ttlDeadline time.Time
		var ttlTables []TableRecord
		var pending []TableRecord
		var databases []DatabaseRecord
		err := c.service.repository.View(c.ctx, func(r Reader) error {
			var err error
			pending, err = r.PendingTables()
			if err != nil {
				return err
			}
			databases, err = r.Databases()
			if err != nil {
				return err
			}
			ttlTables, err = r.TTLTables()
			return err
		})
		if err != nil {
			if c.ctx.Err() != nil {
				return
			}
			slog.Error("DynamoDB engine recovery scan failed", "error", err)
			retry = true
		} else {
			backupDeadline, backupRetry, backupErr := c.service.reconcileBackups(c.ctx)
			if backupErr != nil && c.ctx.Err() == nil {
				slog.Error("DynamoDB backup reconciliation failed", "error", backupErr)
			}
			retry = retry || backupRetry
			for i := range pending {
				again, err := c.service.reconcileTable(c.ctx, &pending[i])
				if err != nil && c.ctx.Err() == nil {
					slog.Error("DynamoDB table reconciliation failed", "table", pending[i].Key.ARN(), "error", err)
				}
				retry = retry || again || err != nil
				if c.ctx.Err() != nil {
					return
				}
			}
			replicaDeadline, replicaRetry, replicaErr := c.service.reconcileReplicas(c.ctx)
			if replicaErr != nil && c.ctx.Err() == nil {
				slog.Error("DynamoDB replica reconciliation failed", "error", replicaErr)
			}
			retry = retry || replicaRetry || replicaErr != nil
			var ttlRetry bool
			ttlDeadline, ttlRetry = c.service.runTTL(c.ctx, ttlTables)
			retry = retry || ttlRetry
			if !replicaDeadline.IsZero() && (ttlDeadline.IsZero() || replicaDeadline.Before(ttlDeadline)) {
				ttlDeadline = replicaDeadline
			}
			if !backupDeadline.IsZero() && (ttlDeadline.IsZero() || backupDeadline.Before(ttlDeadline)) {
				ttlDeadline = backupDeadline
			}
			recoveryDeadline, recoveryRetry, recoveryErr := c.service.maintainRecoveries(c.ctx)
			if recoveryErr != nil && c.ctx.Err() == nil {
				slog.Error("DynamoDB continuous recovery failed", "error", recoveryErr)
			}
			retry = retry || recoveryRetry
			if !recoveryDeadline.IsZero() && (ttlDeadline.IsZero() || recoveryDeadline.Before(ttlDeadline)) {
				ttlDeadline = recoveryDeadline
			}
			streamDeadline, streamPoll, streamErr := c.service.maintainStreams(c.ctx)
			if streamErr != nil && c.ctx.Err() == nil {
				slog.Error("DynamoDB stream recovery failed", "error", streamErr)
			}
			retry = retry || streamPoll || streamErr != nil
			if !streamDeadline.IsZero() && (ttlDeadline.IsZero() || streamDeadline.Before(ttlDeadline)) {
				ttlDeadline = streamDeadline
			}
			// Re-read after stream expiry may have retired a database in this pass.
			if err := c.service.repository.View(c.ctx, func(r Reader) error { var err error; databases, err = r.Databases(); return err }); err != nil {
				retry = true
			}
			if c.ctx.Err() != nil {
				return
			}
			for _, database := range databases {
				if !database.Retiring {
					continue
				}
				if err := c.remove(database); err != nil {
					if c.ctx.Err() != nil {
						return
					}
					slog.Error("DynamoDB database removal failed", "database", database.Spec.ID, "error", err)
					retry = true
				}
			}
		}
		var timer *time.Timer
		var next <-chan time.Time
		if retry {
			timer = time.NewTimer(time.Second)
			next = timer.C
		}
		var expiry clock.Timer
		var expiryC <-chan time.Time
		if !ttlDeadline.IsZero() {
			expiry = c.service.clock.NewTimerAt(ttlDeadline)
			expiryC = expiry.C()
		}
		select {
		case <-c.ctx.Done():
		case <-c.wakeups:
		case <-next:
		case <-expiryC:
		}
		if timer != nil {
			timer.Stop()
		}
		if expiry != nil {
			expiry.Stop()
		}
		if c.ctx.Err() != nil {
			return
		}
	}
}
func (c *engineController) remove(record DatabaseRecord) error {
	release, err := c.lockData(c.ctx, record.Spec.ID)
	if err != nil {
		return err
	}
	defer release()
	c.mu.Lock()
	db := c.databases[record.Spec.ID]
	delete(c.databases, record.Spec.ID)
	c.mu.Unlock()
	if db != nil {
		if err := db.Close(); err != nil {
			return err
		}
	}
	if err := c.service.runtime.Remove(c.ctx, record.Spec); err != nil {
		return err
	}
	return c.service.repository.Update(c.ctx, func(tx Transaction) error { return tx.DeleteDatabase(record.Spec.ID) })
}
func (c *engineController) close() error {
	c.cancel()
	c.mu.Lock()
	c.closed = true
	databases := c.databases
	c.databases = map[string]engine.Database{}
	c.mu.Unlock()
	var result error
	for _, db := range databases {
		result = errors.Join(result, db.Close())
	}
	c.work.Wait()
	return result
}
