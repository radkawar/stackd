package scheduler

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"stackd/clock"
)

type sourceFuncs struct {
	next func(context.Context) (Job, bool, error)
	run  func(context.Context, Job) error
}

func (s sourceFuncs) Next(ctx context.Context) (Job, bool, error) { return s.next(ctx) }
func (s sourceFuncs) Run(ctx context.Context, job Job) error      { return s.run(ctx, job) }

// memorySource models service-owned atomic eligibility/version checks. The
// driver intentionally does not own this persistence or its fencing rules.
type memorySource struct {
	mu      sync.Mutex
	clock   clock.Clock
	jobs    map[string]Job
	onRun   func(Job)
	selects atomic.Int32
}

func newMemorySource(source clock.Clock, jobs ...Job) *memorySource {
	s := &memorySource{clock: source, jobs: make(map[string]Job)}
	for _, job := range jobs {
		s.put(job)
	}
	return s
}

func (s *memorySource) put(job Job) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.jobs[job.Key] = job
}

func (s *memorySource) Next(ctx context.Context) (Job, bool, error) {
	s.selects.Add(1)
	if err := ctx.Err(); err != nil {
		return Job{}, false, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var next Job
	found := false
	for _, job := range s.jobs {
		if !found || Compare(job, next) < 0 {
			next, found = job, true
		}
	}
	return next, found, nil
}

func (s *memorySource) Run(ctx context.Context, selected Job) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	job, found := s.jobs[selected.Key]
	if !found || job.Version != selected.Version || !job.Due.Equal(selected.Due) || job.Due.After(s.clock.Now()) {
		s.mu.Unlock()
		return nil
	}
	delete(s.jobs, job.Key)
	s.mu.Unlock()
	if s.onRun != nil {
		s.onRun(job)
	}
	return nil
}

func schedulerContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func await[T any](t *testing.T, ctx context.Context, ch <-chan T) T {
	t.Helper()
	select {
	case value := <-ch:
		return value
	case <-ctx.Done():
		t.Fatal(ctx.Err())
		var zero T
		return zero
	}
}

func TestDriverOrdersSourcesAndKeysAtZeroEpoch(t *testing.T) {
	epoch := time.Time{}
	clock := clock.NewManual(epoch)
	first := newMemorySource(clock, Job{Key: "b", Due: epoch}, Job{Key: "a", Due: epoch})
	second := newMemorySource(clock, Job{Key: "earlier", Due: epoch.Add(-time.Second)}, Job{Key: "00", Due: epoch}, Job{Key: "future", Due: epoch.Add(time.Second)})
	var actual []string
	first.onRun = func(job Job) { actual = append(actual, "first/"+job.Key) }
	second.onRun = func(job Job) { actual = append(actual, "second/"+job.Key) }
	driver := New(clock, first, second)
	defer driver.Close()
	result, err := driver.RunDue(t.Context(), 10)
	if err != nil || result.Processed != 4 || result.More || result.Next == nil || !result.Next.Equal(epoch.Add(time.Second)) {
		t.Fatalf("result=%+v error=%v", result, err)
	}
	if want := []string{"second/earlier", "first/a", "first/b", "second/00"}; !reflect.DeepEqual(actual, want) {
		t.Fatalf("order=%v, want %v", actual, want)
	}
}

func TestDriverBoundsAndRecursiveWorkUseCapturedHorizon(t *testing.T) {
	epoch := time.Time{}
	clock := clock.NewManual(epoch)
	source := newMemorySource(clock, Job{Key: "parent", Version: 1, Due: epoch})
	source.onRun = func(job Job) {
		if job.Key == "parent" {
			if err := clock.Advance(time.Minute); err != nil {
				t.Error(err)
			}
			source.put(Job{Key: "child", Version: 1, Due: epoch})
			source.put(Job{Key: "later", Version: 1, Due: epoch.Add(time.Minute)})
		}
	}
	driver := New(clock, source)
	defer driver.Close()
	result, err := driver.RunDue(t.Context(), 1)
	if err != nil || result.Processed != 1 || !result.More || result.Next == nil || !result.Next.Equal(epoch) {
		t.Fatalf("bounded result=%+v error=%v", result, err)
	}
	result, err = driver.RunDue(t.Context(), 10)
	if err != nil || result.Processed != 2 || result.More || result.Next != nil {
		t.Fatalf("continued result=%+v error=%v", result, err)
	}
	// Without the artificial one-job bound, the later job must remain pending
	// despite the callback's advance; newly created work at the horizon runs.
	source.put(Job{Key: "parent", Version: 2, Due: clock.Now()})
	epoch = clock.Now()
	result, err = driver.RunDue(t.Context(), 10)
	if err != nil || result.Processed != 2 || result.More || result.Next == nil || !result.Next.Equal(epoch.Add(time.Minute)) {
		t.Fatalf("horizon result=%+v error=%v", result, err)
	}
	if _, err := driver.RunDue(t.Context(), 0); err == nil {
		t.Fatal("zero limit was accepted")
	}
	if _, err := driver.RunDue(t.Context(), -1); err == nil {
		t.Fatal("negative limit was accepted")
	}
}

func TestDriverPassesSelectedVersionForSourceFencing(t *testing.T) {
	clock := clock.NewManual(time.Time{})
	source := newMemorySource(clock, Job{Key: "same", Version: 1, Due: clock.Now()})
	var once sync.Once
	var selected []uint64
	var executed []uint64
	source.onRun = func(job Job) { executed = append(executed, job.Version) }
	fenced := sourceFuncs{
		next: func(ctx context.Context) (Job, bool, error) {
			job, found, err := source.Next(ctx)
			once.Do(func() { source.put(Job{Key: "same", Version: 2, Due: job.Due}) })
			return job, found, err
		},
		run: func(ctx context.Context, job Job) error {
			selected = append(selected, job.Version)
			return source.Run(ctx, job)
		},
	}
	driver := New(clock, fenced)
	defer driver.Close()
	result, err := driver.RunDue(t.Context(), 10)
	if err != nil || result.Processed != 2 || !reflect.DeepEqual(selected, []uint64{1, 2}) || !reflect.DeepEqual(executed, []uint64{2}) {
		t.Fatalf("selected=%v executed=%v result=%+v error=%v", selected, executed, result, err)
	}
}

func TestDriverCancellationWhileWaitingAndDuringSelection(t *testing.T) {
	ctx := schedulerContext(t)
	clock := clock.NewManual(time.Time{})
	source := newMemorySource(clock, Job{Key: "held", Due: clock.Now()})
	entered := make(chan struct{})
	blocking := sourceFuncs{next: source.Next, run: func(ctx context.Context, _ Job) error {
		close(entered)
		<-ctx.Done()
		return ctx.Err()
	}}
	driver := New(clock, blocking)
	defer driver.Close()
	firstCtx, firstCancel := context.WithCancel(ctx)
	defer firstCancel()
	first := make(chan error, 1)
	go func() { _, err := driver.RunDue(firstCtx, 1); first <- err }()
	await(t, ctx, entered)
	secondCtx, secondCancel := context.WithCancel(ctx)
	second := make(chan error, 1)
	go func() { _, err := driver.RunDue(secondCtx, 1); second <- err }()
	secondCancel()
	if err := await(t, ctx, second); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if source.selects.Load() != 1 {
		t.Fatal("waiting drain entered a source")
	}
	firstCancel()
	if err := await(t, ctx, first); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	selectCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	selecting := New(clock, sourceFuncs{
		next: func(context.Context) (Job, bool, error) { cancel(); return Job{Key: "cancelled"}, true, nil },
		run:  func(context.Context, Job) error { t.Error("started a callback after cancellation"); return nil },
	})
	defer selecting.Close()
	if _, err := selecting.RunDue(selectCtx, 1); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func TestDriverConcurrentDrainsAndCloseJoin(t *testing.T) {
	t.Run("serialized drains", func(t *testing.T) {
		ctx := schedulerContext(t)
		clock := clock.NewManual(time.Time{})
		source := newMemorySource(clock)
		for index := range 16 {
			source.put(Job{Key: fmt.Sprintf("%02d", index)})
		}
		var active atomic.Int32
		wrapped := sourceFuncs{next: source.Next, run: func(ctx context.Context, job Job) error {
			if active.Add(1) != 1 {
				t.Error("concurrent Run calls")
			}
			defer active.Add(-1)
			return source.Run(ctx, job)
		}}
		driver := New(clock, wrapped)
		defer driver.Close()
		done := make(chan error, 16)
		for range 16 {
			go func() {
				result, err := driver.RunDue(ctx, 1)
				if err == nil && result.Processed != 1 {
					err = fmt.Errorf("processed %d jobs", result.Processed)
				}
				done <- err
			}()
		}
		for range 16 {
			if err := await(t, ctx, done); err != nil {
				t.Fatal(err)
			}
		}
	})
	t.Run("shutdown joins explicit callbacks", func(t *testing.T) {
		ctx := schedulerContext(t)
		clock := clock.NewManual(time.Time{})
		entered, cancelled, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
		driver := New(clock, sourceFuncs{
			next: func(context.Context) (Job, bool, error) { return Job{Key: "held"}, true, nil },
			run: func(ctx context.Context, _ Job) error {
				close(entered)
				<-ctx.Done()
				close(cancelled)
				<-release
				return ctx.Err()
			},
		})
		ran := make(chan error, 1)
		go func() { _, err := driver.RunDue(ctx, 1); ran <- err }()
		await(t, ctx, entered)
		closed := make(chan struct{}, 4)
		for range 4 {
			go func() { driver.Close(); closed <- struct{}{} }()
		}
		await(t, ctx, cancelled)
		select {
		case <-closed:
			t.Fatal("Close returned before callback exited")
		default:
		}
		close(release)
		for range 4 {
			await(t, ctx, closed)
		}
		if err := await(t, ctx, ran); !errors.Is(err, ErrClosed) {
			t.Fatal(err)
		}
		for range 10 {
			if _, err := driver.RunDue(ctx, 1); !errors.Is(err, ErrClosed) {
				t.Fatalf("closed drain error=%v", err)
			}
		}
		driver.Start()
		driver.Wake()
		driver.Close()
		if clock.Pending() != 0 {
			t.Fatal("closed driver started a timer")
		}
	})
}

func TestDriverPreservesWorkOnSourceErrors(t *testing.T) {
	clock := clock.NewManual(time.Time{})
	source := newMemorySource(clock, Job{Key: "retry"})
	failure := errors.New("storage unavailable")
	for _, during := range []string{"next", "run"} {
		t.Run(during, func(t *testing.T) {
			wrapped := sourceFuncs{next: source.Next, run: source.Run}
			if during == "next" {
				wrapped.next = func(context.Context) (Job, bool, error) { return Job{}, false, failure }
			} else {
				wrapped.run = func(context.Context, Job) error { return failure }
			}
			driver := New(clock, wrapped)
			defer driver.Close()
			result, err := driver.RunDue(t.Context(), 1)
			if !errors.Is(err, failure) || result.Processed != 0 {
				t.Fatalf("result=%+v error=%v", result, err)
			}
			if _, found, err := source.Next(t.Context()); err != nil || !found {
				t.Fatal("failed work was consumed", err)
			}
		})
	}
}
