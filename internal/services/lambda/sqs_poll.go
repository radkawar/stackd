package lambda

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"
)

// The kernel owns only live polls, capacity and ephemeral batching. SQS owns
// visibility, FIFO group exclusion, redrive and crash recovery; no receipt
// ledger is written to Lambda storage. It never runs in scheduler.Drain.
type sqsPollingKernel struct {
	wake      chan struct{}
	done      chan sqsPollCompletion
	throttled chan EventSourceMappingKey
	mappings  map[EventSourceMappingKey]*sqsPollState
}

type sqsPollState struct {
	mapping                    EventSourceMappingRecord
	ctx                        context.Context
	cancel                     context.CancelFunc
	active, capacity, failures int
	next, activity, scaled     time.Time
	provisionedAt              time.Time
	provisionedCount           int
	limiter                    sqsPollRate
	sourceMu                   sync.Mutex
	sourceFunction             FunctionKey
	sourceRole                 string
	sourceConsumer             SQSConsumer
}

type sqsPollCompletion struct {
	state   *sqsPollState
	polled  int
	backoff bool
}

// startSQSPollingLocked is called after Service.started is published, with mu
// held. Register before launch so Close cannot pass work.Wait first.
func (s *Service) startSQSPollingLocked() {
	if s.sqs == nil {
		return
	}
	kernel := &sqsPollingKernel{wake: make(chan struct{}, 1), done: make(chan sqsPollCompletion, 128), throttled: make(chan EventSourceMappingKey, 128), mappings: make(map[EventSourceMappingKey]*sqsPollState)}
	s.sqsPoller = kernel
	s.work.Add(1)
	go func() { defer s.work.Done(); s.runSQSPolling(kernel) }()
}

func (s *Service) eventSourceMappingsChanged() {
	s.jobs.Wake()
	s.mu.Lock()
	kernel := s.sqsPoller
	streamKernel := s.streamPoller
	kafkaKernel := s.kafkaPoller
	mqKernel := s.mqPoller
	documentDBKernel := s.documentDBPoller
	s.mu.Unlock()
	if kernel != nil {
		select {
		case kernel.wake <- struct{}{}:
		default:
		}
	}
	if streamKernel != nil {
		select {
		case streamKernel.wake <- struct{}{}:
		default:
		}
	}
	if kafkaKernel != nil {
		select {
		case kafkaKernel.wake <- struct{}{}:
		default:
		}
	}
	if mqKernel != nil {
		select {
		case mqKernel.wake <- struct{}{}:
		default:
		}
	}
	if documentDBKernel != nil {
		select {
		case documentDBKernel.wake <- struct{}{}:
		default:
		}
	}
}

func (s *Service) runSQSPolling(kernel *sqsPollingKernel) {
	timer := s.clock.NewTimer(0)
	defer timer.Stop()
	defer func() {
		for _, state := range kernel.mappings {
			state.cancel()
		}
	}()
	for {
		select {
		case <-s.lifetime.Done():
			return
		case <-timer.C():
			s.reconcileSQSPolling(kernel)
			timer.Reset(time.Second)
		case <-kernel.wake:
			s.reconcileSQSPolling(kernel)
		case key := <-kernel.throttled:
			if state := kernel.mappings[key]; state != nil {
				floor, _, _ := sqsCapacity(state.mapping.Settings)
				if state.mapping.Settings.ProvisionedPollers == nil {
					floor = 1
				}
				state.capacity = max(floor, state.capacity-1)
				state.next = s.clock.Now().Add(time.Second)
			}
		case result := <-kernel.done:
			state := result.state
			state.active--
			if result.backoff {
				state.failures = min(state.failures+1, 6)
				state.next = s.clock.Now().Add(time.Second * time.Duration(1<<(state.failures-1)))
				floor, _, _ := sqsCapacity(state.mapping.Settings)
				if state.mapping.Settings.ProvisionedPollers == nil {
					floor = 1
				}
				state.capacity = max(floor, state.capacity-1)
			} else if result.polled != 0 {
				state.failures = 0
				state.activity = s.clock.Now()
			} else {
				floor, _, _ := sqsCapacity(state.mapping.Settings)
				state.capacity = max(floor, state.capacity-1)
				// Real long polls wait in SQS. This also bounds sources returning
				// empty immediately, without a wall-clock-only sleep.
				state.next = s.clock.Now().Add(100 * time.Millisecond)
			}
		}
		for _, state := range kernel.mappings {
			s.fillSQSPolls(kernel, state)
		}
	}
}

func sqsCapacity(settings EventSourceMappingSettings) (floor, initial, ceiling int) {
	if p := settings.ProvisionedPollers; p != nil {
		return p.Minimum * 10, p.Minimum * 10, p.Maximum * 10
	}
	floor, initial, ceiling = 2, 5, 1250
	if settings.MaximumConcurrency != nil {
		ceiling = *settings.MaximumConcurrency
		floor = min(5, ceiling)
	}
	return floor, min(initial, ceiling), ceiling
}

func (s *Service) reconcileSQSPolling(kernel *sqsPollingKernel) {
	var rows []EventSourceMappingRecord
	err := s.repository.View(s.lifetime, func(r Reader) error { var err error; rows, err = r.AllEventSourceMappings(); return err })
	if err != nil {
		if !errors.Is(err, context.Canceled) {
			slog.Error("Lambda SQS mapping reconciliation failed", "error", err)
		}
		return
	}
	now := s.clock.Now()
	present := make(map[EventSourceMappingKey]bool, len(rows))
	for _, mapping := range rows {
		if mapping.State != "Enabled" || mapping.Settings.Stream != nil || mapping.Settings.Kafka != nil || mapping.Settings.MQ != nil || mapping.Settings.DocumentDB != nil {
			continue
		}
		present[mapping.Key] = true
		state := kernel.mappings[mapping.Key]
		if state != nil && state.ctx.Err() != nil {
			if state.active != 0 {
				continue
			}
			delete(kernel.mappings, mapping.Key)
			state = nil
		}
		if state == nil {
			_, initial, _ := sqsCapacity(mapping.Settings)
			ctx, cancel := context.WithCancel(ownerContext(s.lifetime, mapping.Function.FunctionKey))
			state = &sqsPollState{ctx: ctx, cancel: cancel, mapping: mapping, capacity: initial, scaled: now}
			kernel.mappings[mapping.Key] = state
		}
		floor, _, ceiling := sqsCapacity(mapping.Settings)
		if mapping.Settings.ProvisionedPollers != nil {
			state.capacity = max(floor, state.capacity)
		}
		state.capacity = min(state.capacity, ceiling)
		state.mapping = mapping
		// AWS documents upper ramp rates, not deterministic per-message timing.
		// No backlog sampling or duplicate SQS queue implementation is needed:
		// recent nonempty completed polls and saturated slots supply demand.
		if state.active >= state.capacity && !state.activity.IsZero() && now.Sub(state.activity) <= 20*time.Second && !now.Before(state.next) {
			rate := float64(300) / 60
			if mapping.Settings.ProvisionedPollers != nil {
				rate = float64(1000) / 60
			}
			growth := int(now.Sub(state.scaled).Seconds() * rate)
			if growth > 0 {
				state.capacity = min(ceiling, state.capacity+growth)
				state.scaled = now
			}
		} else {
			state.scaled = now
		}
		pollers := 0
		if mapping.Settings.ProvisionedPollers != nil {
			pollers = (state.capacity + 9) / 10
		}
		state.limiter.configure(pollers)
		if pollers > 0 && (pollers != state.provisionedCount || now.Sub(state.provisionedAt) >= time.Minute) {
			s.sourceMetric(mapping, "ProvisionedPollers", pollers)
			state.provisionedCount, state.provisionedAt = pollers, now
		}
	}
	for key, state := range kernel.mappings {
		if !present[key] {
			state.cancel()
			if state.active == 0 {
				delete(kernel.mappings, key)
			}
		}
	}
}

func (s *Service) fillSQSPolls(kernel *sqsPollingKernel, state *sqsPollState) {
	if state.ctx.Err() != nil || s.clock.Now().Before(state.next) {
		return
	}
	for state.active < state.capacity {
		s.mu.Lock()
		if s.closed.Load() {
			s.mu.Unlock()
			return
		}
		s.work.Add(1)
		s.mu.Unlock()
		state.active++
		mapping := state.mapping
		go func() {
			defer s.work.Done()
			result := s.runSQSPoll(state.ctx, mapping, state)
			result.state = state
			select {
			case kernel.done <- result:
			case <-s.lifetime.Done():
			}
		}()
	}
}

func (s *Service) sqsThrottleMapping(ctx context.Context, key EventSourceMappingKey) {
	s.mu.Lock()
	kernel := s.sqsPoller
	s.mu.Unlock()
	if kernel != nil {
		select {
		case kernel.throttled <- key:
		case <-ctx.Done():
		}
	}
}

func (s *Service) waitSourceDeadline(ctx context.Context, due time.Time) bool {
	if ctx.Err() != nil {
		return false
	}
	if !due.After(s.clock.Now()) {
		return true
	}
	timer := s.clock.NewTimerAt(due)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C():
		return ctx.Err() == nil
	}
}

// Provisioned capacity is shared by all invocation slots, at ten concurrent
// invokes and ten ReceiveMessage calls/second plus 1 MB/second per poller.
// Reservation timestamps are transient rate budgets, not message recovery data.
type sqsPollRate struct {
	mu              sync.Mutex
	pollers         int
	pollAt, bytesAt time.Time
}

func (r *sqsPollRate) configure(pollers int) { r.mu.Lock(); r.pollers = pollers; r.mu.Unlock() }

func (r *sqsPollRate) reserve(now time.Time, bytes int) time.Time {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.pollers == 0 {
		return now
	}
	if bytes == 0 {
		due := r.pollAt
		if due.Before(now) {
			due = now
		}
		if due.Before(r.bytesAt) {
			due = r.bytesAt
		}
		r.pollAt = due.Add(time.Second / time.Duration(10*r.pollers))
		return due
	}
	if r.bytesAt.Before(now) {
		r.bytesAt = now
	}
	r.bytesAt = r.bytesAt.Add(time.Duration(float64(time.Second) * float64(bytes) / float64(r.pollers*1024*1024)))
	return r.bytesAt
}
