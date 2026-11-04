package sqlite

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	nativesqlite "modernc.org/sqlite"
)

type outcomeNativeConnection interface {
	driver.Conn
	driver.ConnBeginTx
	driver.ConnPrepareContext
	driver.ExecerContext
	driver.QueryerContext
	driver.Pinger
	driver.SessionResetter
	driver.Validator
}

// The observer changes only the Commit boundary. Statements, SAVEPOINTs and
// rollback/durability all use real SQLite, never a substitute persistence engine.
type outcomeCommitObserver struct {
	entered chan struct{}
	release <-chan struct{}
	failure error
	commits atomic.Int64
}

type outcomeConnector struct {
	driver.Connector
	observer *outcomeCommitObserver
}

func (c outcomeConnector) Connect(ctx context.Context) (driver.Conn, error) {
	conn, err := c.Connector.Connect(ctx)
	if err != nil {
		return nil, err
	}
	return outcomeConnection{conn.(outcomeNativeConnection), c.observer}, nil
}

type outcomeConnection struct {
	outcomeNativeConnection
	observer *outcomeCommitObserver
}

func (c outcomeConnection) BeginTx(ctx context.Context, options driver.TxOptions) (driver.Tx, error) {
	tx, err := c.outcomeNativeConnection.BeginTx(ctx, options)
	if err != nil {
		return nil, err
	}
	return outcomeNativeTx{tx, c.observer}, nil
}

type outcomeNativeTx struct {
	driver.Tx
	observer *outcomeCommitObserver
}

func (tx outcomeNativeTx) Commit() error {
	tx.observer.commits.Add(1)
	if tx.observer.entered != nil {
		close(tx.observer.entered)
		<-tx.observer.release
	}
	if tx.observer.failure != nil {
		if err := tx.Tx.Rollback(); err != nil {
			return err
		}
		return tx.observer.failure
	}
	return tx.Tx.Commit()
}

func openOutcomeFixture(t *testing.T, path string, observer *outcomeCommitObserver) *sql.DB {
	t.Helper()
	connector, err := nativesqlite.NewConnector(path + "?_txlock=immediate&_pragma=foreign_keys(1)&_pragma=journal_mode(WAL)&_pragma=synchronous(FULL)")
	if err != nil {
		t.Fatal(err)
	}
	db := sql.OpenDB(outcomeConnector{connector, observer})
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = db.Close() })
	if _, err := db.ExecContext(t.Context(), "CREATE TABLE IF NOT EXISTS outcome_fixture (member TEXT NOT NULL, component TEXT NOT NULL, PRIMARY KEY (member, component))"); err != nil {
		t.Fatal(err)
	}
	var synchronous int
	if err := db.QueryRowContext(t.Context(), "PRAGMA synchronous").Scan(&synchronous); err != nil || synchronous != 2 {
		t.Fatalf("native durability mode = %d, %v; want FULL", synchronous, err)
	}
	return db
}

func writeOutcomePart(ctx context.Context, db *sql.DB, member, component string) error {
	return Transact(ctx, db, false, func(ctx context.Context, tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, "INSERT INTO outcome_fixture (member, component) VALUES (?, ?)", member, component)
		return err
	})
}

func outcomeParts(t *testing.T, db *sql.DB) []string {
	t.Helper()
	rows, err := db.QueryContext(t.Context(), "SELECT member || ':' || component FROM outcome_fixture ORDER BY member, component")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var parts []string
	for rows.Next() {
		var part string
		if err := rows.Scan(&part); err != nil {
			t.Fatal(err)
		}
		parts = append(parts, part)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return parts
}

func startOutcome(g *OutcomeGroup, ctx context.Context, fn func(context.Context) error) <-chan error {
	result := make(chan error, 1)
	go func() { result <- g.Do(ctx, fn) }()
	return result
}

func TestOutcomeGroupAcknowledgesOnlyAfterNativeCommit(t *testing.T) {
	release := make(chan struct{})
	resume := sync.OnceFunc(func() { close(release) })
	defer resume()
	observer := &outcomeCommitObserver{entered: make(chan struct{}), release: release}
	db := openOutcomeFixture(t, filepath.Join(t.TempDir(), "ack.sqlite"), observer)
	g := newOutcomeGroup(db, 2, 2, time.Hour)
	t.Cleanup(func() { resume(); _ = g.Close() })
	first := startOutcome(g, t.Context(), func(ctx context.Context) error {
		return writeOutcomePart(ctx, db, "first", "journal")
	})
	second := startOutcome(g, t.Context(), func(ctx context.Context) error {
		return writeOutcomePart(ctx, db, "second", "journal")
	})
	<-observer.entered
	for _, result := range []<-chan error{first, second} {
		select {
		case err := <-result:
			t.Fatalf("acknowledged before native commit: %v", err)
		default:
		}
	}
	resume()
	for _, result := range []<-chan error{first, second} {
		if err := <-result; err != nil {
			t.Fatal(err)
		}
	}
	if observer.commits.Load() != 1 {
		t.Fatal("members did not share one native commit")
	}
}

func TestOutcomeGroupSavepointIsolationAndReopenDurability(t *testing.T) {
	path := filepath.Join(t.TempDir(), "isolation.sqlite")
	observer := &outcomeCommitObserver{}
	db := openOutcomeFixture(t, path, observer)
	g := newOutcomeGroup(db, 3, 3, time.Hour)
	t.Cleanup(func() { _ = g.Close() })
	rejected := errors.New("one complete sink rejected")
	type callerKey struct{}
	results := make(map[string]<-chan error)
	for _, member := range []string{"first", "rejected", "last"} {
		ctx := context.WithValue(t.Context(), callerKey{}, member)
		deadline := time.Now().Add(time.Hour)
		ctx, cancel := context.WithDeadline(ctx, deadline)
		defer cancel()
		results[member] = startOutcome(g, ctx, func(ctx context.Context) error {
			if got := ctx.Value(callerKey{}); got != member {
				return fmt.Errorf("caller value = %v, want %s", got, member)
			}
			if got, ok := ctx.Deadline(); !ok || !got.Equal(deadline) {
				return fmt.Errorf("caller deadline = %v, %t, want %v", got, ok, deadline)
			}
			for _, component := range []string{"journal", "cloudtrail", "guardduty"} {
				if err := writeOutcomePart(ctx, db, member, component); err != nil {
					return err
				}
				if member == "rejected" && component == "cloudtrail" {
					// A caught nested write error normally poisons its owner;
					// Attempt must confine it to this member's SAVEPOINT.
					_ = Transact(ctx, db, false, func(context.Context, *sql.Tx) error { return rejected })
					return nil
				}
			}
			return nil
		})
	}
	for member, result := range results {
		err := <-result
		if member == "rejected" {
			if !errors.Is(err, rejected) {
				t.Fatalf("rejected member = %v", err)
			}
		} else if err != nil {
			t.Fatalf("successful member %s = %v", member, err)
		}
	}
	if err := g.Close(); err != nil {
		t.Fatal(err)
	}
	if observer.commits.Load() != 1 {
		t.Fatalf("native commits = %d, want one", observer.commits.Load())
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	reopened := openOutcomeFixture(t, path, &outcomeCommitObserver{})
	want := []string{"first:cloudtrail", "first:guardduty", "first:journal", "last:cloudtrail", "last:guardduty", "last:journal"}
	if got := outcomeParts(t, reopened); !reflect.DeepEqual(got, want) {
		t.Fatalf("reopened complete sink parts = %v, want %v", got, want)
	}
}

func TestOutcomeGroupCommitFailureFansOut(t *testing.T) {
	failure := errors.New("native commit unavailable")
	observer := &outcomeCommitObserver{failure: failure}
	db := openOutcomeFixture(t, filepath.Join(t.TempDir(), "failure.sqlite"), observer)
	g := newOutcomeGroup(db, 3, 3, time.Hour)
	t.Cleanup(func() { _ = g.Close() })
	rejected := errors.New("individual sink failure")
	results := []<-chan error{
		startOutcome(g, t.Context(), func(ctx context.Context) error { return writeOutcomePart(ctx, db, "first", "journal") }),
		startOutcome(g, t.Context(), func(ctx context.Context) error {
			if err := writeOutcomePart(ctx, db, "rejected", "journal"); err != nil {
				return err
			}
			return rejected
		}),
		startOutcome(g, t.Context(), func(ctx context.Context) error { return writeOutcomePart(ctx, db, "last", "journal") }),
	}
	for i, result := range results {
		want := failure
		if i == 1 {
			want = rejected
		}
		if err := <-result; !errors.Is(err, want) {
			t.Fatalf("member %d = %v, want %v", i, err, want)
		}
	}
	if got := outcomeParts(t, db); len(got) != 0 {
		t.Fatalf("failed native commit retained %v", got)
	}
}

// Enqueue a known accepted member so cancellation and shutdown can be ordered
// without polling scheduler state or depending on the batch collection timer.
func enqueueOutcome(g *OutcomeGroup, ctx context.Context, fn func(context.Context) error) <-chan error {
	<-g.slots
	request := &outcomeRequest{ctx: ctx, fn: fn, result: make(chan error, 1)}
	g.mu.Lock()
	g.queue <- request
	g.mu.Unlock()
	return request.result
}

func TestOutcomeGroupCancellationIsPerAttempt(t *testing.T) {
	db := openOutcomeFixture(t, filepath.Join(t.TempDir(), "cancel.sqlite"), &outcomeCommitObserver{})
	g := newOutcomeGroup(db, 3, 3, time.Hour)
	t.Cleanup(func() { _ = g.Close() })
	queuedContext, cancelQueued := context.WithCancel(t.Context())
	queued := enqueueOutcome(g, queuedContext, func(context.Context) error {
		return errors.New("canceled queued callback was invoked")
	})
	cancelQueued()
	activeContext, cancelActive := context.WithCancel(t.Context())
	defer cancelActive()
	active := enqueueOutcome(g, activeContext, func(ctx context.Context) error {
		if err := writeOutcomePart(ctx, db, "canceled", "journal"); err != nil {
			return err
		}
		cancelActive()
		<-ctx.Done()
		return nil // Attempt must observe cancellation even if the sink catches it.
	})
	success := startOutcome(g, t.Context(), func(ctx context.Context) error {
		return writeOutcomePart(ctx, db, "accepted", "journal")
	})
	for _, result := range []<-chan error{queued, active} {
		if err := <-result; !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled member = %v", err)
		}
	}
	if err := <-success; err != nil {
		t.Fatalf("other caller was canceled by its peer: %v", err)
	}
	if got := outcomeParts(t, db); !reflect.DeepEqual(got, []string{"accepted:journal"}) {
		t.Fatalf("canceled attempt retained writes: %v", got)
	}
}

type outcomeWaitingContext struct {
	context.Context
	waiting chan struct{}
	once    sync.Once
}

func (c *outcomeWaitingContext) Done() <-chan struct{} {
	c.once.Do(func() { close(c.waiting) })
	return c.Context.Done()
}

func TestOutcomeGroupBoundedBackpressureAndConcurrentClose(t *testing.T) {
	db := openOutcomeFixture(t, filepath.Join(t.TempDir(), "shutdown.sqlite"), &outcomeCommitObserver{})
	g := newOutcomeGroup(db, 1, 1, time.Hour)
	release := make(chan struct{})
	resume := sync.OnceFunc(func() { close(release) })
	t.Cleanup(func() { resume(); _ = g.Close() })
	entered := make(chan struct{})
	first := startOutcome(g, t.Context(), func(ctx context.Context) error {
		close(entered)
		<-release
		return writeOutcomePart(ctx, db, "first", "journal")
	})
	<-entered
	second := enqueueOutcome(g, t.Context(), func(ctx context.Context) error {
		return writeOutcomePart(ctx, db, "second", "journal")
	})
	if len(g.queue) != 1 || len(g.slots) != 0 {
		t.Fatal("queue did not retain its exact bound")
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	waiting := &outcomeWaitingContext{Context: ctx, waiting: make(chan struct{})}
	third := startOutcome(g, waiting, func(context.Context) error {
		return errors.New("backpressured callback ran")
	})
	<-waiting.waiting
	cancel()
	// An accepted call cannot return until the blocked commit. Returning now
	// therefore proves cancellation occurred at admission, outside the queue.
	if err := <-third; !errors.Is(err, context.Canceled) {
		t.Fatalf("backpressure cancellation = %v", err)
	}
	var closers sync.WaitGroup
	closed := make(chan struct{})
	for range 12 {
		closers.Go(func() { _ = g.Close() })
	}
	go func() { closers.Wait(); close(closed) }()
	<-g.stopping
	if err := g.Do(t.Context(), func(context.Context) error { return nil }); !errors.Is(err, ErrOutcomeGroupClosed) {
		t.Fatalf("work admitted during shutdown: %v", err)
	}
	select {
	case <-closed:
		t.Fatal("Close abandoned accepted callbacks")
	default:
	}
	resume()
	for _, result := range []<-chan error{first, second} {
		if err := <-result; err != nil {
			t.Fatal(err)
		}
	}
	<-closed
	if got := outcomeParts(t, db); !reflect.DeepEqual(got, []string{"first:journal", "second:journal"}) {
		t.Fatalf("shutdown did not drain accepted work: %v", got)
	}
}

func TestOutcomeGroupBorrowedTransactionBypassesQueue(t *testing.T) {
	observer := &outcomeCommitObserver{}
	db := openOutcomeFixture(t, filepath.Join(t.TempDir(), "borrowed.sqlite"), observer)
	g := newOutcomeGroup(db, 1, 32, time.Hour)
	t.Cleanup(func() { _ = g.Close() })
	rollback := errors.New("source rejected")
	err := Transact(t.Context(), db, false, func(ctx context.Context, source *sql.Tx) error {
		if err := g.Do(ctx, func(ctx context.Context) error {
			if scope := ctx.Value(transactionKey{db}).(*transactionScope); scope.tx != source {
				return errors.New("group replaced the source transaction")
			}
			return writeOutcomePart(ctx, db, "borrowed", "journal")
		}); err != nil {
			return err
		}
		if len(g.queue) != 0 || len(g.slots) != 1 {
			return errors.New("borrowed outcome entered queue")
		}
		return rollback
	})
	if !errors.Is(err, rollback) {
		t.Fatalf("source transaction = %v", err)
	}
	if got := outcomeParts(t, db); len(got) != 0 || observer.commits.Load() != 0 {
		t.Fatalf("borrowed outcome escaped source rollback: %v, commits %d", got, observer.commits.Load())
	}
}

func TestOutcomeGroupCloseFlushesPartialBatch(t *testing.T) {
	db := openOutcomeFixture(t, filepath.Join(t.TempDir(), "partial.sqlite"), &outcomeCommitObserver{})
	g := newOutcomeGroup(db, 2, 32, time.Hour)
	t.Cleanup(func() { _ = g.Close() })
	result := enqueueOutcome(g, t.Context(), func(ctx context.Context) error {
		return writeOutcomePart(ctx, db, "partial", "journal")
	})
	if err := g.Close(); err != nil {
		t.Fatal(err)
	}
	if err := <-result; err != nil {
		t.Fatal(err)
	}
	if got := outcomeParts(t, db); !reflect.DeepEqual(got, []string{"partial:journal"}) {
		t.Fatalf("shutdown lost a partial batch: %v", got)
	}
}

func TestOutcomeGroupPartialBatchCollectionDeadline(t *testing.T) {
	db := openOutcomeFixture(t, filepath.Join(t.TempDir(), "collection.sqlite"), &outcomeCommitObserver{})
	g := newOutcomeGroup(db, 2, 32, 0)
	t.Cleanup(func() { _ = g.Close() })
	if err := g.Do(t.Context(), func(ctx context.Context) error {
		return writeOutcomePart(ctx, db, "partial", "journal")
	}); err != nil {
		t.Fatal(err)
	}
	if got := outcomeParts(t, db); !reflect.DeepEqual(got, []string{"partial:journal"}) {
		t.Fatalf("collection deadline lost a partial batch: %v", got)
	}
}

func TestOutcomeGroupPanicReturnsToItsCallerAfterSavepointRollback(t *testing.T) {
	db := openOutcomeFixture(t, filepath.Join(t.TempDir(), "panic.sqlite"), &outcomeCommitObserver{})
	g := newOutcomeGroup(db, 2, 2, time.Hour)
	t.Cleanup(func() { _ = g.Close() })
	panicked := make(chan any, 1)
	go func() {
		defer func() { panicked <- recover() }()
		_ = g.Do(t.Context(), func(ctx context.Context) error {
			if err := writeOutcomePart(ctx, db, "panicked", "journal"); err != nil {
				return err
			}
			panic("original sink panic")
		})
	}()
	other := startOutcome(g, t.Context(), func(ctx context.Context) error {
		return writeOutcomePart(ctx, db, "accepted", "journal")
	})
	if got := <-panicked; got != "original sink panic" {
		t.Fatalf("caller recovered %v", got)
	}
	if err := <-other; err != nil {
		t.Fatal(err)
	}
	if got := outcomeParts(t, db); !reflect.DeepEqual(got, []string{"accepted:journal"}) {
		t.Fatalf("panic escaped its SAVEPOINT: %v", got)
	}
}

func TestOutcomeGroupCloseWaitsForAcceptedInlineCallback(t *testing.T) {
	db := openOutcomeFixture(t, filepath.Join(t.TempDir(), "inline-close.sqlite"), &outcomeCommitObserver{})
	g := newOutcomeGroup(db, 1, 32, time.Hour)
	release, entered := make(chan struct{}), make(chan struct{})
	resume := sync.OnceFunc(func() { close(release) })
	t.Cleanup(func() { resume(); _ = g.Close() })
	source := make(chan error, 1)
	go func() {
		source <- Transact(t.Context(), db, false, func(ctx context.Context, _ *sql.Tx) error {
			return g.Do(ctx, func(ctx context.Context) error {
				close(entered)
				<-release
				return writeOutcomePart(ctx, db, "inline", "journal")
			})
		})
	}()
	<-entered
	closed := make(chan struct{})
	go func() { _ = g.Close(); close(closed) }()
	<-g.stopping
	select {
	case <-closed:
		t.Fatal("Close abandoned an accepted inline callback")
	default:
	}
	resume()
	if err := <-source; err != nil {
		t.Fatal(err)
	}
	<-closed
}
