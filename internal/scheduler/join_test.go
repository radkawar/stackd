package scheduler

import (
	"context"
	"errors"
	"reflect"
	"sync"
	"testing"
	"time"

	"stackd/clock"
)

func TestJoinedDriversShareOrderWakeAndShutdown(t *testing.T) {
	ctx := schedulerContext(t)
	epoch := time.Time{}
	manual := clock.NewManual(epoch)
	firstSource := newMemorySource(manual, Job{Key: "a", Due: epoch})
	secondSource := newMemorySource(manual, Job{Key: "b", Due: epoch.Add(-time.Second)}, Job{Key: "c", Due: epoch}, Job{Key: "d", Due: epoch.Add(time.Second)})
	ran := make(chan string, 4)
	firstSource.onRun = func(job Job) { ran <- job.Key }
	secondSource.onRun = func(job Job) { ran <- job.Key }
	first, second := New(manual, firstSource), New(manual, secondSource)
	joined, err := Join(nil, first, second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(joined.Close)
	result, err := second.RunDue(ctx, 2)
	if err != nil || result.Processed != 2 || !result.More || result.Next == nil || !result.Next.Equal(epoch) {
		t.Fatal("joined bounded drain", result, err)
	}
	if a, b := await(t, ctx, ran), await(t, ctx, ran); a != "b" || b != "a" {
		t.Fatal("deadline and source ordering", a, b)
	}
	result, err = first.RunDue(ctx, 1)
	if err != nil || result.Processed != 1 || result.More || result.Next == nil || !result.Next.Equal(epoch.Add(time.Second)) {
		t.Fatal("joined continuation", result, err)
	}
	if key := await(t, ctx, ran); key != "c" {
		t.Fatal(key)
	}
	if err := manual.Advance(time.Second); err != nil {
		t.Fatal(err)
	}
	second.Wake()
	if key := await(t, ctx, ran); key != "d" {
		t.Fatal("joined wake did not recover work", key)
	}
	first.Close()
	if _, err := second.RunDue(ctx, 1); !errors.Is(err, ErrClosed) {
		t.Fatal("joined shutdown did not close the other handle", err)
	}
	second.Close()
	if manual.Pending() != 0 {
		t.Fatal("joined shutdown retained worker timers")
	}
}

func TestJoinedReadSnapshotEndsBeforeRunAndDiscoversCrossSourceWork(t *testing.T) {
	ctx := schedulerContext(t)
	epoch := time.Time{}
	manual := clock.NewManual(epoch)
	first := newMemorySource(manual, Job{Key: "parent", Due: epoch})
	second := newMemorySource(manual, Job{Key: "future", Due: epoch.Add(time.Second)})
	var ran []string
	first.onRun = func(job Job) {
		ran = append(ran, job.Key)
		second.put(Job{Key: "child", Due: epoch})
	}
	second.onRun = func(job Job) { ran = append(ran, job.Key) }

	var storage sync.RWMutex
	read := func(ctx context.Context, scan func(context.Context) error) error {
		storage.RLock()
		defer storage.RUnlock()
		borrowed, cancel := context.WithCancel(ctx)
		defer cancel()
		return scan(borrowed)
	}
	wrap := func(source *memorySource) Source {
		return sourceFuncs{
			next: func(ctx context.Context) (Job, bool, error) {
				if storage.TryLock() {
					storage.Unlock()
					return Job{}, false, errors.New("selection escaped its read snapshot")
				}
				return source.Next(ctx)
			},
			run: func(ctx context.Context, job Job) error {
				if err := ctx.Err(); err != nil {
					return err
				}
				if !storage.TryLock() {
					return errors.New("execution cannot write while the read snapshot is held")
				}
				defer storage.Unlock()
				return source.Run(ctx, job)
			},
		}
	}
	driver, err := Join(read, New(manual, wrap(first)), New(manual, wrap(second)))
	if err != nil {
		t.Fatal(err)
	}
	defer driver.Close()
	result, err := driver.RunDue(ctx, 10)
	if err != nil || result.Processed != 2 || result.More || result.Next == nil || !result.Next.Equal(epoch.Add(time.Second)) {
		t.Fatalf("result=%+v error=%v", result, err)
	}
	if want := []string{"parent", "child"}; !reflect.DeepEqual(ran, want) {
		t.Fatalf("executed=%v, want %v", ran, want)
	}
}

func TestJoinedReadFailureDoesNotExecuteSelectedWork(t *testing.T) {
	for _, failureAt := range []string{"open", "selection", "close", "cancelled snapshot"} {
		t.Run(failureAt, func(t *testing.T) {
			manual := clock.NewManual(time.Time{})
			source := newMemorySource(manual, Job{Key: "pending"})
			failure := errors.New("read failed")
			if failureAt == "cancelled snapshot" {
				failure = context.Canceled
			}
			var cancelSnapshot context.CancelFunc
			read := func(ctx context.Context, scan func(context.Context) error) error {
				if failureAt == "open" {
					return failure
				}
				ctx, cancelSnapshot = context.WithCancel(ctx)
				defer cancelSnapshot()
				if err := scan(ctx); err != nil {
					return err
				}
				if failureAt == "close" {
					return failure
				}
				return nil
			}
			wrapped := sourceFuncs{
				next: func(ctx context.Context) (Job, bool, error) {
					job, found, err := source.Next(ctx)
					switch failureAt {
					case "selection":
						return Job{}, false, failure
					case "cancelled snapshot":
						cancelSnapshot()
					}
					return job, found, err
				},
				run: source.Run,
			}
			driver, err := Join(read, New(manual, wrapped))
			if err != nil {
				t.Fatal(err)
			}
			defer driver.Close()
			result, err := driver.RunDue(t.Context(), 1)
			if !errors.Is(err, failure) || result.Processed != 0 {
				t.Fatalf("result=%+v error=%v, want %v", result, err, failure)
			}
			if _, found, err := source.Next(t.Context()); err != nil || !found {
				t.Fatal("read failure consumed pending work", err)
			}
		})
	}
}
