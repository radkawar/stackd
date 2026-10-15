package ebs

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"
)

type nativeEffects struct {
	mu      sync.Mutex
	ctx     context.Context
	cancel  context.CancelFunc
	work    sync.WaitGroup
	active  bool
	closed  bool
	retryAt time.Time
}

// Native callers include EC2 workers. A canceled consumer must not wait for a
// dependency's uncanceled disk work before that dependency can be closed.
// Like the shared scheduler's gate, this lock does not close its token channel.
// Its zero value is usable and allocates only when native work first starts.
type nativeWorkMutex struct {
	once sync.Once
	gate chan struct{}
}

func (m *nativeWorkMutex) Lock(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	m.once.Do(func() { m.gate = make(chan struct{}, 1) })
	select {
	case <-ctx.Done():
		return ctx.Err()
	case m.gate <- struct{}{}:
		if err := ctx.Err(); err != nil {
			<-m.gate
			return err
		}
		return nil
	}
}

func (m *nativeWorkMutex) Unlock() { <-m.gate }

// Persisted records own recovery. Dispatch never holds the shared service-time
// drain while copying snapshot blocks or calling the native disk backend.
func (s *Service) dispatchNativeWork(ctx context.Context) error {
	s.native.mu.Lock()
	available, retryAt := !s.native.active && !s.native.closed, s.native.retryAt
	s.native.mu.Unlock()
	if !available {
		return nil
	}
	now := s.clock.Now()
	if retryAt.After(now) {
		return nil
	}
	pending := false
	err := s.repository.View(ctx, func(r Reader) error {
		snapshot, volume, due, err := s.nextEBSWork(r, true, time.Time{})
		if err != nil {
			return err
		}
		pending = !due.After(now) && (volume.Key.ID != "" && s.volumeNeedsNativeWork(volume) || snapshot.Key.ID != "" && snapshotNeedsNativeWork(snapshot))
		return nil
	})
	if errors.Is(err, ErrNotFound) {
		return nil
	}
	if err != nil || !pending {
		return err
	}
	s.native.mu.Lock()
	defer s.native.mu.Unlock()
	if s.native.closed || s.native.active || s.native.retryAt.After(now) {
		return nil
	}
	if s.native.ctx == nil {
		s.native.ctx, s.native.cancel = context.WithCancel(context.Background())
	}
	s.native.active = true
	s.native.work.Go(func() {
		ctx := s.native.ctx
		err := s.advanceNativeWork(ctx)
		if err != nil && ctx.Err() == nil {
			slog.ErrorContext(ctx, "EBS native reconciliation failed", "error", err)
		}
		s.native.mu.Lock()
		s.native.active = false
		s.native.retryAt = time.Time{}
		if err != nil && ctx.Err() == nil {
			// Keep the scheduler's existing one-second failure retry interval.
			s.native.retryAt = s.clock.Now().Add(time.Second)
		}
		closed := s.native.closed
		s.native.mu.Unlock()
		if !closed {
			s.jobs.Wake()
		}
	})
	return nil
}
