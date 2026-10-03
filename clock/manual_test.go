package clock_test

import (
	"context"
	"errors"
	"math"
	"sync"
	"testing"
	"time"

	"stackd/clock"
)

func received(t *testing.T, timer clock.Timer, want time.Time) {
	t.Helper()
	select {
	case got := <-timer.C():
		if !got.Equal(want) {
			t.Fatalf("timer sent %s; want %s", got, want)
		}
	default:
		t.Fatal("due timer did not fire")
	}
}

func empty(t *testing.T, timer clock.Timer) {
	t.Helper()
	select {
	case got := <-timer.C():
		t.Fatalf("unexpected timer firing at %s", got)
	default:
	}
}

func advance(t *testing.T, manual *clock.Manual, d time.Duration) {
	t.Helper()
	if err := manual.Advance(d); err != nil {
		t.Fatal(err)
	}
}

func TestManualDeadlinesAndUTC(t *testing.T) {
	start := time.Date(2026, 9, 11, 14, 0, 0, 7, time.FixedZone("fixture", 3600))
	m := clock.NewManual(start)
	if got := m.Now(); !got.Equal(start) || got.Location() != time.UTC {
		t.Fatalf("initial time = %s (%s)", got, got.Location())
	}
	immediate := []clock.Timer{m.NewTimer(0), m.NewTimer(-time.Second), m.NewTimer(time.Duration(math.MinInt64)), m.NewTimerAt(start), m.NewTimerAt(start.Add(-time.Hour))}
	for _, timer := range immediate {
		received(t, timer, start)
		empty(t, timer)
		if timer.Stop() {
			t.Fatal("consumed timer reported active")
		}
	}
	if m.Pending() != 0 {
		t.Fatal("immediate firings remain scheduled")
	}
	first := m.NewTimer(5 * time.Second)
	second := m.NewTimerAt(start.Add(10 * time.Second))
	if m.Pending() != 2 {
		t.Fatal("missing registrations")
	}
	advance(t, m, 4*time.Second)
	empty(t, first)
	empty(t, second)
	advance(t, m, time.Second)
	received(t, first, start.Add(5*time.Second))
	empty(t, second)
	if m.Pending() != 1 {
		t.Fatal("fired timer is retained")
	}
	advance(t, m, 100*time.Second)
	// Advancing past a deadline preserves its scheduled timestamp.
	received(t, second, start.Add(10*time.Second))
	if !m.Now().Equal(start.Add(105*time.Second)) || m.Pending() != 0 {
		t.Fatal("incorrect final clock state")
	}
	advance(t, m, time.Hour)
	empty(t, first)
	empty(t, second)
}

func TestManualStopAndResetDiscardStaleFirings(t *testing.T) {
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	m := clock.NewManual(start)
	timer := m.NewTimer(time.Hour)
	if !timer.Stop() || timer.Stop() {
		t.Fatal("Stop must report active once")
	}
	if m.Pending() != 0 {
		t.Fatal("stopped timer retained")
	}
	if timer.Reset(10 * time.Second) {
		t.Fatal("Reset of stopped timer reported active")
	}
	if !timer.Reset(20 * time.Second) {
		t.Fatal("Reset of scheduled timer reported inactive")
	}
	advance(t, m, 10*time.Second)
	empty(t, timer)
	advance(t, m, 10*time.Second)
	if !timer.Stop() {
		t.Fatal("Stop must cancel an unread firing")
	}
	empty(t, timer)
	if timer.Reset(time.Second) {
		t.Fatal("stopped timer reported active")
	}
	advance(t, m, time.Second)
	if !timer.Reset(2 * time.Second) {
		t.Fatal("Reset must cancel an unread firing")
	}
	empty(t, timer)
	advance(t, m, time.Second)
	empty(t, timer)
	advance(t, m, time.Second)
	received(t, timer, start.Add(23*time.Second))
	if timer.Reset(0) {
		t.Fatal("consumed timer reported active")
	}
	if !timer.Reset(-time.Second) {
		t.Fatal("unread immediate timer reported inactive")
	}
	received(t, timer, m.Now())
	empty(t, timer)
	if timer.Stop() || m.Pending() != 0 {
		t.Fatal("consumed timer is still scheduled")
	}
}

func TestManualAdvanceErrorsAndLargeDurations(t *testing.T) {
	m := clock.NewManual(time.Unix(0, 0))
	timer := m.NewTimer(time.Duration(math.MaxInt64))
	if err := m.Advance(-1); !errors.Is(err, clock.ErrBackwardAdvance) {
		t.Fatalf("negative advance = %v", err)
	}
	if !m.Now().Equal(time.Unix(0, 0)) || m.Pending() != 1 {
		t.Fatal("failed advance changed state")
	}
	advance(t, m, 0)
	empty(t, timer)
	advance(t, m, time.Duration(math.MaxInt64)-1)
	empty(t, timer)
	advance(t, m, time.Nanosecond)
	received(t, timer, time.Unix(0, 0).Add(time.Duration(math.MaxInt64)))

	// time.Time stores seconds relative to year 1 in a signed int64. This is
	// the last representable instant, beyond the normal Unix timestamp horizon.
	const unixToYearOne = 62135596800
	last := time.Unix(math.MaxInt64-unixToYearOne, 999999999).UTC()
	m = clock.NewManual(last.Add(-time.Second))
	due := m.NewTimerAt(last)
	unreachable := m.NewTimer(2 * time.Second)
	advance(t, m, time.Second)
	received(t, due, last)
	if err := m.Advance(time.Nanosecond); !errors.Is(err, clock.ErrTimeOverflow) {
		t.Fatalf("overflow advance = %v", err)
	}
	if !m.Now().Equal(last) || m.Pending() != 1 {
		t.Fatal("overflow changed clock or timer state")
	}
	empty(t, unreachable)
	if !unreachable.Reset(0) {
		t.Fatal("overflow timer could not be reset")
	}
	received(t, unreachable, last)
	if m.Pending() != 0 {
		t.Fatal("overflow timer retained after reset")
	}
}

func TestManualAbsoluteDeadlineDoesNotShiftDuringRegistration(t *testing.T) {
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	m := clock.NewManual(start)
	deadline := m.Now().Add(time.Minute)
	advanced := make(chan struct{})
	go func() {
		_ = m.Advance(2 * time.Minute)
		close(advanced)
	}()
	<-advanced
	timer := m.NewTimerAt(deadline)
	received(t, timer, start.Add(2*time.Minute))
	if m.Pending() != 0 {
		t.Fatal("past absolute deadline was shifted into the future")
	}

	// Absolute timers also work beyond time.Duration's roughly 292-year range.
	m = clock.NewManual(start)
	distant := start.AddDate(400, 0, 0)
	timer = m.NewTimerAt(distant)
	advance(t, m, time.Duration(math.MaxInt64))
	empty(t, timer)
	advance(t, m, distant.Sub(m.Now()))
	received(t, timer, distant)
}

func TestManualWaitForTimersAndCancellation(t *testing.T) {
	m := clock.NewManual(time.Time{})
	if err := m.WaitForTimers(t.Context(), 0); err != nil {
		t.Fatal(err)
	}
	if err := m.WaitForTimers(t.Context(), -1); !errors.Is(err, clock.ErrInvalidTimerCount) {
		t.Fatalf("negative timer count = %v", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- m.WaitForTimers(ctx, 2) }()
	one := m.NewTimer(time.Hour)
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled wait = %v", err)
	}
	if err := m.WaitForTimers(ctx, 0); !errors.Is(err, context.Canceled) {
		t.Fatalf("already canceled wait = %v", err)
	}

	const count = 8
	var waiters sync.WaitGroup
	for range count {
		waiters.Go(func() {
			if err := m.WaitForTimers(t.Context(), 3); err != nil {
				t.Error(err)
			}
		})
	}
	var timers []clock.Timer
	for range 3 {
		timers = append(timers, m.NewTimer(time.Minute))
	}
	if err := m.WaitForTimers(t.Context(), 3); err != nil {
		t.Fatal(err)
	}
	waiters.Wait()
	if !one.Stop() {
		t.Fatal("missing original timer")
	}
	advance(t, m, time.Minute)
	for _, timer := range timers {
		received(t, timer, m.Now())
	}
	if m.Pending() != 0 {
		t.Fatal("completed timers retained")
	}
}

func TestManualConcurrentRegistrationAdvanceResetAndStop(t *testing.T) {
	m := clock.NewManual(time.Unix(0, 0))
	const count = 128
	timers := make([]clock.Timer, count)
	var workers sync.WaitGroup
	for i := range count {
		workers.Go(func() { timers[i] = m.NewTimerAt(time.Unix(1, 0)) })
	}
	if err := m.WaitForTimers(t.Context(), count); err != nil {
		t.Fatal(err)
	}
	workers.Wait()
	advance(t, m, time.Second)
	for _, timer := range timers {
		received(t, timer, time.Unix(1, 0))
	}

	shared := m.NewTimer(time.Hour)
	for range 8 {
		workers.Go(func() {
			for range 200 {
				shared.Reset(time.Nanosecond)
				_ = m.Now()
				_ = m.Pending()
				if err := m.Advance(time.Nanosecond); err != nil {
					t.Error(err)
				}
				shared.Stop()
			}
		})
	}
	workers.Wait()
	shared.Stop()
	empty(t, shared)
	if m.Pending() != 0 {
		t.Fatal("concurrent Stop/Reset retained timers")
	}
}

func TestManualAdvanceDoesNotDrainReceivingGoroutines(t *testing.T) {
	m := clock.NewManual(time.Unix(0, 0))
	release := make(chan struct{})
	done := make(chan struct{})
	go func() {
		first := m.NewTimer(time.Second)
		<-first.C()
		<-release
		second := m.NewTimer(time.Second)
		<-second.C()
		close(done)
	}()
	if err := m.WaitForTimers(t.Context(), 1); err != nil {
		t.Fatal(err)
	}
	advance(t, m, time.Second)
	if m.Pending() != 0 {
		t.Fatal("Advance unexpectedly scheduled a blocked goroutine's next timer")
	}
	close(release)
	if err := m.WaitForTimers(t.Context(), 1); err != nil {
		t.Fatal(err)
	}
	advance(t, m, time.Second)
	<-done
}

func TestManualZeroValue(t *testing.T) {
	var m clock.Manual
	if !m.Now().IsZero() {
		t.Fatal("zero clock has nonzero time")
	}
	timer := m.NewTimer(time.Second)
	advance(t, &m, time.Second)
	received(t, timer, time.Time{}.Add(time.Second))
}
