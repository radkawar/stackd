// Package scheduler runs ordered work from service-owned transactional job
// records. It owns execution and wakeups; sources own persistence and fencing.
package scheduler

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"time"

	"stackd/clock"
)

var ErrClosed = errors.New("job driver is closed")
var ErrInvalidLimit = errors.New("job drain limit must be positive")

// Job identifies a persisted intent. Key is stable within its source; Version
// fences replacement. Due may be the zero epoch and is never an absence marker.
type Job struct {
	Key     string
	Version uint64
	Due     time.Time
}

// Source returns its earliest outstanding job, ordered by deadline then key.
// Next must not mutate resource storage or perform external effects; in-memory
// selection caches are allowed.
// Run must revalidate eligibility and version in the owning transaction. A
// successful run consumes or reschedules work; stale selections are harmless.
// Next may join a shared read snapshot, which closes before any Run call.
// Methods must honor context cancellation so Driver.Close can join them.
// They may call Wake, but must not synchronously drain or close the same driver.
type Source interface {
	Next(context.Context) (Job, bool, error)
	Run(context.Context, Job) error
}

// Result describes one bounded drain, including the next persisted deadline.
// Processed counts successful Run calls, including fenced stale selections.
type Result struct {
	Processed int        `json:"processed"`
	More      bool       `json:"more"`
	Next      *time.Time `json:"next,omitempty"`
}

// Driver serializes automatic and explicit drains. Equal deadlines use source
// registration order, then each source's stable key order.
// Selection may share a read snapshot; execution remains service-owned.
type Driver struct{ *execution }

// execution is shared by drivers joined during service assembly. Keeping one
// execution object makes wakeups, explicit drains and shutdown use the same gate.
type execution struct {
	clock   clock.Clock
	sources []Source
	read    func(context.Context, func(context.Context) error) error
	gate    chan struct{}
	wake    chan struct{}
	ctx     context.Context
	cancel  context.CancelFunc
	done    chan struct{}
	mu      sync.Mutex
	started bool
	closed  bool
}

func New(source clock.Clock, sources ...Source) *Driver {
	if source == nil {
		source = clock.Real{}
	}
	ctx, cancel := context.WithCancel(context.Background())
	d := &execution{clock: source, sources: append([]Source(nil), sources...), gate: make(chan struct{}, 1), wake: make(chan struct{}, 1), ctx: ctx, cancel: cancel, done: make(chan struct{})}
	d.gate <- struct{}{}
	return &Driver{d}
}

// Start recovers persisted work and begins automatic draining. It is idempotent.
func (d *execution) Start() {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.started || d.closed {
		return
	}
	d.started = true
	go d.run()
}

// Wake is an after-commit hint. Coalescing it cannot discard persisted jobs.
func (d *execution) Wake() {
	d.Start()
	select {
	case d.wake <- struct{}{}:
	default:
	}
}

// RunDue executes at most limit jobs due at the clock instant captured after
// acquiring the drain. It includes work created by earlier callbacks when that
// work is also due. Cancellation and shutdown interrupt waiting for the drain.
func (d *execution) RunDue(ctx context.Context, limit int) (Result, error) {
	if limit <= 0 {
		return Result{}, ErrInvalidLimit
	}
	ctx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(d.ctx, cancel)
	defer stop()
	defer cancel()
	select {
	case <-ctx.Done():
		return Result{}, d.drainError(ctx)
	case <-d.ctx.Done():
		return Result{}, ErrClosed
	case <-d.gate:
	}
	defer func() { d.gate <- struct{}{} }()
	if err := d.drainError(ctx); err != nil {
		return Result{}, err
	}
	horizon := d.clock.Now()
	result := Result{}
	for {
		if err := d.drainError(ctx); err != nil {
			return result, err
		}
		job, source, found, err := d.next(ctx)
		if cancelled := d.drainError(ctx); cancelled != nil {
			return result, cancelled
		}
		if err != nil || !found {
			return result, err
		}
		due := !job.Due.After(horizon)
		if !due || result.Processed == limit {
			result.Next, result.More = &job.Due, due
			return result, nil
		}
		if err := source.Run(ctx, job); err != nil {
			if cancelled := d.drainError(ctx); cancelled != nil {
				return result, cancelled
			}
			slog.ErrorContext(ctx, "Service-time job failed", "key", job.Key, "due", job.Due, "error", err)
			return result, err
		}
		result.Processed++
	}
}

func (d *execution) drainError(ctx context.Context) error {
	if d.ctx.Err() != nil {
		return ErrClosed
	}
	return ctx.Err()
}

func (d *execution) next(ctx context.Context) (Job, Source, bool, error) {
	var next Job
	var chosen Source
	scan := func(ctx context.Context) error {
		for _, source := range d.sources {
			if err := ctx.Err(); err != nil {
				return err
			}
			job, found, err := source.Next(ctx)
			if err != nil {
				return err
			}
			if found && (chosen == nil || job.Due.Before(next.Due)) {
				next, chosen = job, source
			}
		}
		return ctx.Err()
	}
	var err error
	if d.read == nil {
		err = scan(ctx)
	} else {
		err = d.read(ctx, scan)
	}
	if err != nil {
		return Job{}, nil, false, err
	}
	return next, chosen, chosen != nil, nil
}

// Compare orders records within a source; source registration resolves ties
// between different sources. Versions identify replacements, not priorities.
func Compare(a, b Job) int {
	if order := a.Due.Compare(b.Due); order != 0 {
		return order
	}
	return strings.Compare(a.Key, b.Key)
}

// Close cancels background and explicit work and joins callbacks before return.
// It never closes the supplied clock or any repository.
func (d *execution) Close() {
	d.mu.Lock()
	d.closed = true
	started := d.started
	d.cancel()
	d.mu.Unlock()
	if started {
		<-d.done
	}
	<-d.gate
	d.gate <- struct{}{}
}
