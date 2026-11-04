package iam

import (
	"context"
	"sync"
	"time"
)

type activityRuntime struct {
	mu      sync.Mutex
	pending *activityBatch
	order   uint64
	started bool
	closed  bool
	stop    chan struct{}
	done    chan struct{}
	flush   chan struct{}
}

func newActivityRuntime() *activityRuntime {
	return &activityRuntime{stop: make(chan struct{}), done: make(chan struct{}), flush: make(chan struct{}, 1)}
}

func (r *activityRuntime) startLocked(s *Service) {
	if r.started || r.closed {
		return
	}
	r.started = true
	go func() {
		defer close(r.done)
		// Reporting cadence is wall time, not modeled service time: manual
		// clock advances must not force reporting I/O onto request paths.
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-r.stop:
				return
			case <-ticker.C:
				// A failure remains pending for the next ordinary tick or an
				// explicit drain. It never changes a data-plane outcome.
				_ = s.FlushActivity(context.Background())
			}
		}
	}()
}

func (s *Service) startActivityWorker() {
	r := s.activity
	r.mu.Lock()
	r.startLocked(s)
	r.mu.Unlock()
}

// FlushActivity durably drains all observations accepted before its snapshot.
// Concurrent enqueues continue into a fresh batch without waiting for storage.
// Flushes serialize; a canceled or failed flush retains its entire snapshot for
// the next normal flush. The context controls only this drain, not any request
// whose immutable observation was accepted earlier.
func (s *Service) FlushActivity(ctx context.Context) error {
	r := s.activity
	select {
	case r.flush <- struct{}{}:
		defer func() { <-r.flush }()
	case <-ctx.Done():
		return ctx.Err()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	r.mu.Lock()
	batch := r.pending
	r.pending = nil
	r.mu.Unlock()
	if batch == nil {
		return nil
	}
	if err := s.writeActivity(ctx, batch); err != nil {
		r.mu.Lock()
		if r.pending == nil {
			r.pending = batch
		} else {
			r.pending.merge(batch)
		}
		r.mu.Unlock()
		return err
	}
	return nil
}

func (s *Service) closeActivity() error {
	r := s.activity
	r.mu.Lock()
	r.closed = true
	started := r.started
	close(r.stop)
	r.mu.Unlock()
	if started {
		<-r.done
	}
	return s.FlushActivity(context.Background())
}
