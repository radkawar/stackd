package memory_test

import (
	"context"
	"errors"
	"maps"
	"sync"
	"testing"
	"time"

	"stackd/storage/memory"
)

func TestCommitAndRollback(t *testing.T) {
	store := memory.New(nil, map[string]int{"count": 1}, maps.Clone[map[string]int])
	boom := errors.New("operation failed")
	for _, cause := range []string{"error", "cancel", "panic"} {
		t.Run(cause, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			var escaped *memory.Transaction
			var err error
			func() {
				if cause == "panic" {
					defer func() {
						if got := recover(); got != boom {
							t.Fatalf("panic = %v", got)
						}
					}()
				}
				err = store.Update(ctx, func(state *map[string]int, tx *memory.Transaction) error {
					escaped = tx
					(*state)["count"] = 99
					switch cause {
					case "error":
						return boom
					case "cancel":
						cancel()
						return nil
					default:
						panic(boom)
					}
				})
			}()
			if cause == "error" && !errors.Is(err, boom) {
				t.Fatalf("error = %v", err)
			}
			if cause == "cancel" && !errors.Is(err, context.Canceled) {
				t.Fatalf("error = %v", err)
			}
			if !errors.Is(escaped.Check(false), memory.ErrClosedTransaction) {
				t.Fatal("transaction remains open")
			}
			if err := store.View(t.Context(), func(state *map[string]int, _ *memory.Transaction) error {
				if (*state)["count"] != 1 {
					t.Fatal("failed transaction changed committed state")
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
	if err := store.Update(t.Context(), func(state *map[string]int, _ *memory.Transaction) error { (*state)["count"]++; return nil }); err != nil {
		t.Fatal(err)
	}
	if err := store.View(t.Context(), func(state *map[string]int, _ *memory.Transaction) error {
		if (*state)["count"] != 2 {
			t.Fatal("successful transaction did not commit")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestCancellationWhileWaiting(t *testing.T) {
	for _, holderWrite := range []bool{false, true} {
		for _, waiterWrite := range []bool{false, true} {
			if !holderWrite && !waiterWrite {
				continue
			}
			store := memory.New(nil, 0, func(v int) int { return v })
			holder, waiter := store.View, store.View
			if holderWrite {
				holder = store.Update
			}
			if waiterWrite {
				waiter = store.Update
			}
			entered, release := make(chan struct{}), make(chan struct{})
			holderDone := make(chan error, 1)
			go func() {
				holderDone <- holder(t.Context(), func(_ *int, _ *memory.Transaction) error { close(entered); <-release; return nil })
			}()
			<-entered
			ctx, cancel := context.WithCancel(t.Context())
			waiterDone := make(chan error, 1)
			go func() {
				waiterDone <- waiter(ctx, func(_ *int, _ *memory.Transaction) error { return errors.New("canceled callback ran") })
			}()
			cancel()
			select {
			case err := <-waiterDone:
				if !errors.Is(err, context.Canceled) {
					t.Errorf("canceled waiter: %v", err)
				}
			case <-time.After(3 * time.Second):
				t.Error("canceled waiter is still blocked on the holder")
			}
			close(release)
			if err := <-holderDone; err != nil {
				t.Fatal(err)
			}
		}
	}
}

func TestConcurrentReadersAndClosedTransactions(t *testing.T) {
	store := memory.New(nil, 7, func(v int) int { return v })
	release := make(chan struct{})
	entered := make(chan *memory.Transaction, 2)
	done := make(chan error, 2)
	for range 2 {
		go func() {
			done <- store.View(t.Context(), func(state *int, tx *memory.Transaction) error {
				if *state != 7 {
					return errors.New("incorrect snapshot")
				}
				if !errors.Is(tx.Check(true), memory.ErrClosedTransaction) {
					return errors.New("read-only transaction permits writes")
				}
				entered <- tx
				<-release
				return nil
			})
		}()
	}
	var transactions []*memory.Transaction
	for range 2 {
		select {
		case tx := <-entered:
			transactions = append(transactions, tx)
		case <-time.After(3 * time.Second):
			t.Error("readers did not enter concurrently")
		}
	}
	close(release)
	for range 2 {
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	}
	for _, tx := range transactions {
		if !errors.Is(tx.Check(false), memory.ErrClosedTransaction) {
			t.Fatal("reader remains open")
		}
	}
}

func TestSerializableUpdatesRunOnce(t *testing.T) {
	store := memory.New(nil, 0, func(v int) int { return v })
	var workers sync.WaitGroup
	for range 24 {
		workers.Go(func() {
			for range 30 {
				calls := 0
				if err := store.Update(t.Context(), func(state *int, _ *memory.Transaction) error { calls++; *state++; return nil }); err != nil {
					t.Error(err)
				}
				if calls != 1 {
					t.Errorf("callback invoked %d times", calls)
				}
			}
		})
	}
	workers.Wait()
	if err := store.View(t.Context(), func(state *int, _ *memory.Transaction) error {
		if *state != 720 {
			t.Errorf("lost update: %d", *state)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestCanceledCallbacksAndClonePanic(t *testing.T) {
	for _, write := range []bool{false, true} {
		store := memory.New(nil, 0, func(v int) int { return v })
		run := store.View
		if write {
			run = store.Update
		}
		ctx, cancel := context.WithCancel(t.Context())
		err := run(ctx, func(_ *int, tx *memory.Transaction) error {
			cancel()
			if !errors.Is(tx.Check(false), context.Canceled) {
				t.Fatal("transaction missed cancellation")
			}
			return nil
		})
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("callback cancellation: %v", err)
		}
		err = run(ctx, func(_ *int, _ *memory.Transaction) error { t.Error("pre-canceled callback executed"); return nil })
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("pre-canceled transaction: %v", err)
		}
	}
	panicClone := true
	store := memory.New(nil, 9, func(v int) int {
		if panicClone {
			panic("clone")
		}
		return v
	})
	func() {
		defer func() {
			if recover() != "clone" {
				t.Fatal("clone panic lost")
			}
		}()
		_ = store.Update(t.Context(), func(_ *int, _ *memory.Transaction) error { t.Error("callback ran after clone panic"); return nil })
	}()
	panicClone = false
	if err := store.Update(t.Context(), func(state *int, _ *memory.Transaction) error {
		if *state != 9 {
			t.Fatal("clone panic corrupted state")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
