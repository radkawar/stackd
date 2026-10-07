package lambda

import (
	"context"
	"log/slog"
	"slices"
	"time"
)

// armIdle runs under the execution and service locks after availability is
// published. Runtime cleanup is owned by releaseExecution, never this lock.
func (s *Service) armIdle(slot *execution) {
	if slot.environment == nil || slot.provisionedGeneration != "" {
		return
	}
	due := slot.lastUse.Add(s.keepAlive)
	if refresh := slot.expires.Add(-time.Minute); refresh.Before(due) {
		due = refresh
	}
	if slot.idleTimer != nil {
		slot.idleTimer.Reset(due.Sub(s.clock.Now()))
		return
	}
	timer := s.clock.NewTimerAt(due)
	done := make(chan struct{})
	slot.idleTimer = timer
	slot.stopIdle = func() { timer.Stop(); close(done); slot.idleTimer = nil; slot.stopIdle = nil }
	s.work.Add(1)
	go func() {
		defer s.work.Done()
		defer timer.Stop()
		for {
			select {
			case <-s.lifetime.Done():
				return
			case <-done:
				return
			case <-timer.C():
			}
			slot.mu.Lock()
			if slot.idleTimer != timer {
				slot.mu.Unlock()
				return
			}
			due := slot.lastUse.Add(s.keepAlive)
			if refresh := slot.expires.Add(-time.Minute); refresh.Before(due) {
				due = refresh
			}
			if s.clock.Now().Before(due) {
				timer.Reset(due.Sub(s.clock.Now()))
				slot.mu.Unlock()
				continue
			}
			cleanup, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			err := slot.close(cleanup)
			cancel()
			if err != nil {
				slog.Error("Lambda idle cleanup failed", "function", slot.key.ARN(), "error", err)
			}
			s.mu.Lock()
			s.collectExecutionLocked(slot)
			s.mu.Unlock()
			s.reconcileExecutionImages(slot)
			slot.mu.Unlock()
			return
		}
	}()
}

// releaseExecution runs under the slot lock. A reservation change never retires
// a slot; deployment replacement, deletion and shutdown retire it after work.
func (s *Service) releaseExecution(slot *execution) {
	s.mu.Lock()
	if slot.provisionedGeneration != "" && slot.environment == nil {
		slot.provisionedReady = false
		slot.retiring = true
		s.provisionedChangedLocked()
	}
	if slot.retiring || s.closed.Load() || s.keepAlive == 0 && slot.provisionedGeneration == "" {
		s.mu.Unlock()
		cleanup, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		if err := slot.close(cleanup); err != nil {
			slog.Error("Lambda environment cleanup failed; retained for shutdown retry", "function", slot.key.ARN(), "error", err)
		}
		cancel()
		s.mu.Lock()
	}
	s.releaseExecutionLocked(slot)
	s.mu.Unlock()
	s.reconcileExecutionImages(slot)
}

// releaseExecutionLocked publishes availability and timer ownership together.
// Both locks are held; any required external cleanup has already completed.
func (s *Service) releaseExecutionLocked(slot *execution) {
	slot.leased = false
	if !slot.retiring && !s.closed.Load() && s.keepAlive != 0 {
		s.armIdle(slot)
	}
	s.collectExecutionLocked(slot)
}

// collectExecutionLocked removes an empty slot with both locks held. A failed
// engine cleanup remains owned by the service for shutdown's existing retry.
func (s *Service) collectExecutionLocked(slot *execution) {
	if slot.leased || slot.environment != nil || len(slot.retired) != 0 {
		return
	}
	pool := s.environments[slot.key]
	index := slices.Index(pool, slot)
	pool = slices.Delete(pool, index, index+1)
	if len(pool) == 0 {
		delete(s.environments, slot.key)
	} else {
		s.environments[slot.key] = pool
	}
}

// retireExecutionsLocked runs under Service.mu. Busy environments finish their
// current calls; idle slots are leased to the returned cleanup owner.
func (s *Service) retireExecutionsLocked(key FunctionVersionKey, keep *execution) []*execution {
	var idle []*execution
	for _, slot := range s.environments[key] {
		if slot == keep {
			continue
		}
		slot.retiring = true
		if !slot.leased {
			slot.leased = true
			idle = append(idle, slot)
		}
	}
	return idle
}

func (s *Service) retireFunctionExecutionsLocked(key FunctionKey) []*execution {
	var idle []*execution
	for version := range s.environments {
		if version.FunctionKey == key {
			idle = append(idle, s.retireExecutionsLocked(version, nil)...)
		}
	}
	return idle
}

func (s *Service) closeIdleExecutions(slots []*execution) {
	for _, slot := range slots {
		slot.mu.Lock()
		s.releaseExecution(slot)
		slot.mu.Unlock()
	}
}
