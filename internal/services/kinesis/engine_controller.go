package kinesis

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"

	"stackd/clock"
	engine "stackd/engine/kinesis"
)

// engineController owns native handles and serializes a stream's append/reshard/
// trim boundaries without holding a repository transaction during external I/O.
type engineController struct {
	service         *Service
	ctx             context.Context
	cancel          context.CancelFunc
	mu              sync.Mutex
	started, closed bool
	wakeups         chan struct{}
	logs            map[string]engine.Log
	gates           map[string]chan struct{}
	work            sync.WaitGroup
}

func newEngineController(s *Service) *engineController {
	ctx, cancel := context.WithCancel(context.Background())
	return &engineController{service: s, ctx: ctx, cancel: cancel, wakeups: make(chan struct{}, 1), logs: map[string]engine.Log{}, gates: map[string]chan struct{}{}}
}

func (s *Service) Start() error {
	if err := s.engines.start(); err != nil {
		return err
	}
	s.jobs.Start()
	return nil
}

func (s *Service) Close() error {
	s.engines.cancel()
	s.jobs.Close()
	s.consumers.close()
	s.encryption.close()
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
		return errors.New("kinesis service is closed")
	}
	if c.started || c.service.runtime == nil {
		return nil
	}
	c.started = true
	c.work.Add(1)
	go c.run()
	return nil
}

func (c *engineController) log(ctx context.Context, spec engine.Specification) (engine.Log, error) {
	ctx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(c.ctx, cancel)
	defer stop()
	defer cancel()
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil, errors.New("kinesis service is closed")
	}
	if log := c.logs[spec.ID]; log != nil {
		c.mu.Unlock()
		return log, nil
	}
	c.mu.Unlock()
	if c.service.runtime == nil {
		return nil, errors.New("kinesis record runtime is not configured")
	}
	log, err := c.service.runtime.Open(ctx, spec)
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		_ = log.Close()
		return nil, errors.New("kinesis service is closed")
	}
	if existing := c.logs[spec.ID]; existing != nil {
		_ = log.Close()
		return existing, nil
	}
	c.logs[spec.ID] = log
	return log, nil
}

func (c *engineController) lock(ctx context.Context, id string) (func(), error) {
	c.mu.Lock()
	gate := c.gates[id]
	if gate == nil {
		gate = make(chan struct{}, 1)
		gate <- struct{}{}
		c.gates[id] = gate
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
	for c.ctx.Err() == nil {
		var streams []StreamRecord
		err := c.service.repository.View(c.ctx, func(r Reader) error {
			var err error
			streams, err = r.AllStreams()
			return err
		})
		retry := err != nil
		var deadline time.Time
		if err != nil && c.ctx.Err() == nil {
			slog.Error("Kinesis engine recovery scan failed", "error", err)
		}
		for _, stream := range streams {
			next, err := c.service.reconcileStream(c.ctx, stream)
			if err != nil && c.ctx.Err() == nil {
				slog.Error("Kinesis stream reconciliation failed", "stream", stream.Key.ARN(), "error", err)
				retry = true
			}
			deadline = earlierDeadline(deadline, next)
			if c.ctx.Err() != nil {
				return
			}
		}
		// Native process recovery uses wall time. Service lifecycles and record
		// retention use only the injected clock and can be advanced explicitly.
		var recovery *time.Timer
		var recoveryC <-chan time.Time
		if retry {
			recovery = time.NewTimer(time.Second)
			recoveryC = recovery.C
		}
		var timer clock.Timer
		var timerC <-chan time.Time
		if !deadline.IsZero() {
			timer = c.service.clock.NewTimerAt(deadline)
			timerC = timer.C()
		}
		select {
		case <-c.ctx.Done():
		case <-c.wakeups:
		case <-recoveryC:
		case <-timerC:
		}
		if recovery != nil {
			recovery.Stop()
		}
		if timer != nil {
			timer.Stop()
		}
	}
}

func earlierDeadline(a, b time.Time) time.Time {
	if a.IsZero() || (!b.IsZero() && b.Before(a)) {
		return b
	}
	return a
}

func (c *engineController) forget(id string) error {
	c.mu.Lock()
	log := c.logs[id]
	delete(c.logs, id)
	c.mu.Unlock()
	if log != nil {
		return log.Close()
	}
	return nil
}

func (c *engineController) close() error {
	c.cancel()
	c.mu.Lock()
	c.closed = true
	logs := c.logs
	c.logs = map[string]engine.Log{}
	c.mu.Unlock()
	var result error
	for _, log := range logs {
		result = errors.Join(result, log.Close())
	}
	c.work.Wait()
	return result
}
