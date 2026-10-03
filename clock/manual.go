package clock

import (
	"container/heap"
	"context"
	"errors"
	"math"
	"slices"
	"sync"
	"time"
)

var (
	ErrBackwardAdvance   = errors.New("manual clock cannot advance backward")
	ErrTimeOverflow      = errors.New("manual clock advance exceeds representable time")
	ErrInvalidTimerCount = errors.New("timer count cannot be negative")
)

// Manual is a thread-safe UTC clock. Its zero value starts at the zero time;
// NewManual selects an explicit epoch. Do not copy it after use.
//
// Equal-deadline timers are delivered in registration order. Reset is a new
// registration. Delivery order does not determine which receiving goroutine
// runs first, or which ready channel a select chooses.
type Manual struct {
	mu       sync.Mutex
	now      time.Time
	timers   timerHeap
	sequence uint64
	changed  chan struct{}
	advance  chan struct{}
	storage  Storage
}

// NewManual constructs a clock at start, normalized to UTC without a monotonic
// reading. Wall-clock changes do not affect it.
func NewManual(start time.Time) *Manual { return &Manual{now: start.UTC()} }

func (m *Manual) Now() time.Time {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.now
}

// NewTimer schedules relative to the current modeled time atomically. Zero and
// negative durations deliver immediately at the current time. If a positive
// duration exceeds time.Time's representable range, the timer remains pending
// until stopped or reset; the clock cannot advance to its deadline.
func (m *Manual) NewTimer(d time.Duration) Timer {
	m.mu.Lock()
	defer m.mu.Unlock()
	t := &manualTimer{clock: m, channel: make(chan time.Time, 1), index: -1}
	m.schedule(t, d)
	return t
}

// NewTimerAt atomically compares and registers deadline. A past/current deadline
// delivers immediately with the current time. A future deadline delivers that
// deadline, even if a later Advance passes it by a larger interval.
func (m *Manual) NewTimerAt(deadline time.Time) Timer {
	m.mu.Lock()
	defer m.mu.Unlock()
	t := &manualTimer{clock: m, channel: make(chan time.Time, 1), index: -1}
	m.register(t, deadline.UTC(), false)
	return t
}

// Advance moves time forward and delivers all currently registered due timers
// without blocking on receivers. It does not wait for receiving goroutines or
// timers those goroutines may subsequently register. Errors leave time and
// timers unchanged. Advance(0) is valid.
func (m *Manual) Advance(d time.Duration) error {
	return m.AdvanceContext(context.Background(), d)
}

// AdvanceContext is Advance with cancellable storage and serialization waits.
// Persistent clocks save the new instant before exposing it or firing timers.
// A successful storage commit is published even if ctx is canceled afterwards.
func (m *Manual) AdvanceContext(ctx context.Context, d time.Duration) error {
	if d < 0 {
		return ErrBackwardAdvance
	}
	m.mu.Lock()
	if m.advance == nil {
		m.advance = make(chan struct{}, 1)
		m.advance <- struct{}{}
	}
	gate := m.advance
	m.mu.Unlock()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-gate:
	}
	defer func() { gate <- struct{}{} }()
	if err := ctx.Err(); err != nil {
		return err
	}
	m.mu.Lock()
	at, ok := addTime(m.now, d)
	m.mu.Unlock()
	if !ok {
		return ErrTimeOverflow
	}
	// Resource transactions can read Now while holding storage. Do not hold
	// the timer/Now mutex while waiting for that same storage transaction.
	if m.storage != nil {
		if err := m.storage.SetTime(ctx, at); err != nil {
			return err
		}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.now = at
	for len(m.timers) > 0 {
		t := m.timers[0]
		if t.overflow || t.deadline.After(at) {
			break
		}
		heap.Pop(&m.timers)
		t.deliver(t.deadline)
	}
	m.shrink()
	m.notify()
	return nil
}

// Pending counts scheduled timers, excluding stopped timers and already
// delivered notifications (whether or not a receiver has consumed them).
func (m *Manual) Pending() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.timers)
}

// WaitForTimers waits until at least n timers are pending. It observes a count,
// not particular timer identities, and does not reserve timers against another
// goroutine advancing or stopping them. Canceled contexts return promptly;
// negative n returns ErrInvalidTimerCount.
func (m *Manual) WaitForTimers(ctx context.Context, n int) error {
	if n < 0 {
		return ErrInvalidTimerCount
	}
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		m.mu.Lock()
		if len(m.timers) >= n {
			m.mu.Unlock()
			return ctx.Err()
		}
		if m.changed == nil {
			m.changed = make(chan struct{})
		}
		changed := m.changed
		m.mu.Unlock()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-changed:
		}
	}
}

func addTime(at time.Time, d time.Duration) (time.Time, bool) {
	result := at.Add(d)
	// time.Time.Add may saturate its seconds field; the inverse check detects
	// that without subtracting timestamps through a duration that can overflow.
	return result, !result.Before(at) && result.Add(-d).Equal(at)
}

func (m *Manual) schedule(t *manualTimer, d time.Duration) {
	if d <= 0 {
		m.register(t, m.now, false)
		return
	}
	deadline, ok := addTime(m.now, d)
	m.register(t, deadline, !ok)
}

func (m *Manual) register(t *manualTimer, deadline time.Time, overflow bool) {
	t.deadline, t.overflow = deadline, overflow
	if !overflow && !deadline.After(m.now) {
		t.deliver(m.now)
		return
	}
	if m.sequence == math.MaxUint64 {
		// Preserve relative registration order without wrapping the tie-breaker.
		ordered := slices.Clone(m.timers)
		slices.SortFunc(ordered, func(a, b *manualTimer) int {
			if a.sequence < b.sequence {
				return -1
			}
			if a.sequence > b.sequence {
				return 1
			}
			return 0
		})
		for i, pending := range ordered {
			pending.sequence = uint64(i) + 1
		}
		m.sequence = uint64(len(ordered))
	}
	m.sequence++
	t.sequence = m.sequence
	heap.Push(&m.timers, t)
	m.notify()
}

func (m *Manual) notify() {
	if m.changed != nil {
		close(m.changed)
		m.changed = nil
	}
}

func (m *Manual) shrink() {
	if len(m.timers) == 0 {
		m.timers = nil
	} else if cap(m.timers) > 64 && len(m.timers) < cap(m.timers)/4 {
		m.timers = slices.Clone(m.timers)
	}
}

var _ Clock = (*Manual)(nil)
