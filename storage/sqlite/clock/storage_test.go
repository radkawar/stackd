package clock_test

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"stackd/clock"
	"stackd/storage/sqlite"
	sqlclock "stackd/storage/sqlite/clock"
)

func TestPersistentAdvanceCommitsBeforeTimeAndTimersBecomeVisible(t *testing.T) {
	path := filepath.Join(t.TempDir(), "time.sqlite")
	db, err := sqlite.Open(t.Context(), path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	store := sqlclock.New(db)
	absent, err := clock.OpenManual(t.Context(), store, nil)
	if err != nil || absent != nil {
		t.Fatal("opening unconfigured time initialized a clock", err)
	}
	initial := time.Date(2031, 2, 3, 4, 5, 0, 123456789, time.FixedZone("offset", 3600))
	source, err := clock.OpenManual(t.Context(), store, &initial)
	if err != nil {
		t.Fatal(err)
	}
	timer := source.NewTimer(time.Minute)
	defer timer.Stop()
	// Exercise an actual SQLite write rejection; neither the public clock nor
	// its timers may observe an instant that storage rejected.
	if _, err := db.ExecContext(t.Context(), "CREATE TRIGGER reject_clock BEFORE UPDATE ON clock_state BEGIN SELECT RAISE(ABORT, 'clock write failed'); END"); err != nil {
		t.Fatal(err)
	}
	if err := source.AdvanceContext(t.Context(), time.Minute); err == nil {
		t.Fatal("failed write advanced time")
	}
	if !source.Now().Equal(initial) {
		t.Fatal("failed write became visible")
	}
	select {
	case <-timer.C():
		t.Fatal("failed write fired a timer")
	default:
	}
	if _, err := db.ExecContext(t.Context(), "DROP TRIGGER reject_clock"); err != nil {
		t.Fatal(err)
	}
	if err := source.AdvanceContext(t.Context(), time.Minute); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-timer.C():
		if !got.Equal(initial.Add(time.Minute)) {
			t.Fatal("timer fired at the wrong instant")
		}
	default:
		t.Fatal("committed advance did not fire timer")
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	db, err = sqlite.Open(t.Context(), path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	conflictingInitial := initial.Add(-24 * time.Hour)
	restored, err := clock.OpenManual(t.Context(), sqlclock.New(db), &conflictingInitial)
	if err != nil || !restored.Now().Equal(initial.Add(time.Minute)) || restored.Now().Location() != time.UTC {
		t.Fatal("reopen lost the committed instant or reset to the requested seed", err)
	}
}

func TestPersistentAdvanceDoesNotLockResourceClockReads(t *testing.T) {
	db, err := sqlite.Open(t.Context(), filepath.Join(t.TempDir(), "time.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	initial := time.Date(2031, 2, 3, 4, 5, 0, 0, time.UTC)
	source, err := clock.OpenManual(t.Context(), sqlclock.New(db), &initial)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	err = sqlite.Transact(ctx, db, false, func(txctx context.Context, _ *sql.Tx) error {
		// Publication cannot borrow an outer resource transaction whose commit
		// may still fail. Reject it before touching durable or visible time.
		if err := source.AdvanceContext(txctx, time.Second); err == nil {
			t.Fatal("advance borrowed an uncommitted transaction")
		}
		advanceCtx, stop := context.WithCancel(ctx)
		defer stop()
		result := make(chan error, 1)
		waiting := db.Stats().WaitCount
		go func() { result <- source.AdvanceContext(advanceCtx, time.Second) }()
		for db.Stats().WaitCount == waiting {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(time.Millisecond):
			}
		}
		// The update is waiting on this transaction, but resource code must still
		// be able to sample modeled time and register timers while holding storage.
		reads := make(chan time.Time, 1)
		go func() { timer := source.NewTimer(time.Second); defer timer.Stop(); reads <- source.Now() }()
		select {
		case got := <-reads:
			if !got.Equal(initial) {
				t.Fatal("uncommitted time exposed")
			}
		case <-ctx.Done():
			return ctx.Err()
		}
		stop()
		select {
		case err := <-result:
			if !errors.Is(err, context.Canceled) {
				t.Fatal("storage wait did not honor cancellation", err)
			}
		case <-ctx.Done():
			return ctx.Err()
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if !source.Now().Equal(initial) {
		t.Fatal("canceled advance changed time")
	}
	if err := source.AdvanceContext(t.Context(), time.Second); err != nil {
		t.Fatal("failed wait poisoned later advances", err)
	}
}

type cancelAfterCommit struct {
	clock.Storage
	cancel context.CancelFunc
}

func (s cancelAfterCommit) SetTime(ctx context.Context, instant time.Time) error {
	err := s.Storage.SetTime(ctx, instant)
	if err == nil {
		s.cancel()
	}
	return err
}

func TestPersistentAdvancePublishesCommittedTimeAfterCancellation(t *testing.T) {
	db, err := sqlite.Open(t.Context(), filepath.Join(t.TempDir(), "time.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	initial := time.Date(2031, 2, 3, 4, 5, 0, 0, time.UTC)
	store := cancelAfterCommit{Storage: sqlclock.New(db), cancel: cancel}
	source, err := clock.OpenManual(ctx, store, &initial)
	if err != nil {
		t.Fatal(err)
	}
	timer := source.NewTimer(time.Second)
	defer timer.Stop()
	if err := source.AdvanceContext(ctx, time.Second); err != nil {
		t.Fatal("committed advance reported failure", err)
	}
	if ctx.Err() == nil || !source.Now().Equal(initial.Add(time.Second)) {
		t.Fatal("cancellation hid a committed advance")
	}
	select {
	case <-timer.C():
	default:
		t.Fatal("cancellation suppressed a committed timer notification")
	}
	saved, found, err := store.Initialize(t.Context(), nil)
	if err != nil || !found || !saved.Equal(source.Now()) {
		t.Fatal("visible time differs from committed time", err)
	}
}
