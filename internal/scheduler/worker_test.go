package scheduler

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"stackd/clock"
)

type observedClock struct {
	*clock.Manual
	deadlines chan time.Time
	beforeAt  func(time.Time)
	relative  atomic.Int32
}

func newObservedClock(epoch time.Time) *observedClock {
	return &observedClock{Manual: clock.NewManual(epoch), deadlines: make(chan time.Time, 1024)}
}

func (c *observedClock) NewTimer(duration time.Duration) clock.Timer {
	c.relative.Add(1)
	return c.Manual.NewTimer(duration)
}

func (c *observedClock) NewTimerAt(deadline time.Time) clock.Timer {
	if c.beforeAt != nil {
		c.beforeAt(deadline)
	}
	timer := c.Manual.NewTimerAt(deadline)
	c.deadlines <- deadline
	return timer
}

func awaitDeadline(t *testing.T, ctx context.Context, c *observedClock, deadline time.Time) {
	t.Helper()
	for {
		if got := await(t, ctx, c.deadlines); got.Equal(deadline) {
			return
		}
	}
}

func TestWorkerStartupWakeAndExternalCommitRecovery(t *testing.T) {
	ctx := schedulerContext(t)
	epoch := time.Time{}
	clock := newObservedClock(epoch)
	source := newMemorySource(clock.Manual, Job{Key: "persisted", Due: epoch})
	ran := make(chan string, 10)
	source.onRun = func(job Job) { ran <- job.Key }
	driver := New(clock, source)
	t.Cleanup(driver.Close)
	driver.Start()
	driver.Start()
	if key := await(t, ctx, ran); key != "persisted" {
		t.Fatal(key)
	}
	awaitDeadline(t, ctx, clock, epoch.Add(time.Second))
	// Another repository client cannot deliver this driver's wake hint.
	source.put(Job{Key: "external", Due: epoch})
	if err := clock.Advance(time.Second); err != nil {
		t.Fatal(err)
	}
	if key := await(t, ctx, ran); key != "external" {
		t.Fatal(key)
	}
	awaitDeadline(t, ctx, clock, epoch.Add(2*time.Second))
	deadline := clock.Now().Add(100 * time.Millisecond)
	source.put(Job{Key: "woken", Due: deadline})
	driver.Wake()
	awaitDeadline(t, ctx, clock, deadline)
	if clock.Pending() != 1 {
		t.Fatal("wake leaked the replaced recovery timer")
	}
	if err := clock.Advance(100*time.Millisecond - time.Nanosecond); err != nil {
		t.Fatal(err)
	}
	select {
	case key := <-ran:
		t.Fatalf("ran %s before its deadline", key)
	default:
	}
	if err := clock.Advance(time.Nanosecond); err != nil {
		t.Fatal(err)
	}
	if key := await(t, ctx, ran); key != "woken" {
		t.Fatal(key)
	}
	awaitDeadline(t, ctx, clock, clock.Now().Add(time.Second))
	driver.Close()
	if clock.Pending() != 0 || clock.relative.Load() != 0 {
		t.Fatalf("pending=%d relative registrations=%d", clock.Pending(), clock.relative.Load())
	}
}

func TestWorkerRetryUsesAbsoluteRecoveryDeadline(t *testing.T) {
	for _, advanceDuringFailure := range []bool{false, true} {
		t.Run(fmt.Sprint(advanceDuringFailure), func(t *testing.T) {
			ctx := schedulerContext(t)
			epoch := time.Time{}
			clock := newObservedClock(epoch)
			source := newMemorySource(clock.Manual, Job{Key: "recover", Due: epoch})
			failed, ran := make(chan struct{}), make(chan struct{}, 1)
			source.onRun = func(Job) { ran <- struct{}{} }
			var failure atomic.Bool
			failure.Store(true)
			wrapped := sourceFuncs{run: source.Run, next: func(ctx context.Context) (Job, bool, error) {
				if failure.CompareAndSwap(true, false) {
					if advanceDuringFailure {
						if err := clock.Advance(2 * time.Second); err != nil {
							t.Error(err)
						}
					}
					close(failed)
					return Job{}, false, errors.New("transient repository failure")
				}
				return source.Next(ctx)
			}}
			driver := New(clock, wrapped)
			t.Cleanup(driver.Close)
			driver.Start()
			await(t, ctx, failed)
			awaitDeadline(t, ctx, clock, epoch.Add(time.Second))
			if !advanceDuringFailure {
				if err := clock.Advance(time.Second - time.Nanosecond); err != nil {
					t.Fatal(err)
				}
				select {
				case <-ran:
					t.Fatal("retried before one-second recovery deadline")
				default:
				}
				if err := clock.Advance(time.Nanosecond); err != nil {
					t.Fatal(err)
				}
			}
			await(t, ctx, ran)
			driver.Close()
			if clock.Pending() != 0 {
				t.Fatal("retry left a timer after close")
			}
		})
	}
}

func TestWorkerAdvanceDuringTimerRegistrationDoesNotDelayJob(t *testing.T) {
	ctx := schedulerContext(t)
	clock := newObservedClock(time.Time{})
	source := newMemorySource(clock.Manual, Job{Key: "race", Due: clock.Now().Add(500 * time.Millisecond)})
	ran := make(chan struct{}, 1)
	source.onRun = func(Job) { ran <- struct{}{} }
	var once sync.Once
	clock.beforeAt = func(time.Time) {
		once.Do(func() {
			if err := clock.Advance(time.Second); err != nil {
				t.Error(err)
			}
		})
	}
	driver := New(clock, source)
	t.Cleanup(driver.Close)
	driver.Start()
	await(t, ctx, ran)
	driver.Close()
	if clock.Pending() != 0 || clock.relative.Load() != 0 {
		t.Fatal("worker used a relative timer or leaked its final absolute timer")
	}
}

func TestWorkerContinuesBoundedBatchesWithoutManualAdvance(t *testing.T) {
	ctx := schedulerContext(t)
	clock := newObservedClock(time.Time{})
	source := newMemorySource(clock.Manual)
	for index := range 600 {
		source.put(Job{Key: fmt.Sprintf("%03d", index)})
	}
	ran := make(chan string, 600)
	source.onRun = func(job Job) { ran <- job.Key }
	driver := New(clock, source)
	t.Cleanup(driver.Close)
	driver.Start()
	for index := range 600 {
		if key := await(t, ctx, ran); key != fmt.Sprintf("%03d", index) {
			t.Fatalf("job %d=%s", index, key)
		}
	}
	awaitDeadline(t, ctx, clock, clock.Now().Add(time.Second))
	if !clock.Now().IsZero() {
		t.Fatal("driver advanced the caller-owned clock")
	}
	driver.Close()
	if clock.Pending() != 0 {
		t.Fatal("bounded continuation timer survived shutdown")
	}
}

func TestWorkerAndExplicitDrainsShareGate(t *testing.T) {
	ctx := schedulerContext(t)
	clock := newObservedClock(time.Time{})
	source := newMemorySource(clock.Manual, Job{Key: "automatic"}, Job{Key: "explicit"})
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	var active atomic.Int32
	wrapped := sourceFuncs{next: source.Next, run: func(ctx context.Context, job Job) error {
		if active.Add(1) != 1 {
			t.Error("automatic and explicit drains overlapped")
		}
		defer active.Add(-1)
		once.Do(func() {
			close(entered)
			select {
			case <-ctx.Done():
			case <-release:
			}
		})
		return source.Run(ctx, job)
	}}
	driver := New(clock, wrapped)
	t.Cleanup(driver.Close)
	driver.Start()
	await(t, ctx, entered)
	done := make(chan error, 1)
	go func() { _, err := driver.RunDue(ctx, 10); done <- err }()
	close(release)
	if err := await(t, ctx, done); err != nil {
		t.Fatal(err)
	}
	driver.Close()
	if _, found, err := source.Next(ctx); err != nil || found {
		t.Fatal("work was lost across automatic and explicit drains", err)
	}
}
