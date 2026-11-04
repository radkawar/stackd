package sqlite

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"net/url"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	nativesqlite "modernc.org/sqlite"
)

type laneGate struct {
	entered chan struct{}
	release chan struct{}
	pause   sync.Once
	resume  sync.Once
}

func newLaneGate() *laneGate {
	return &laneGate{entered: make(chan struct{}), release: make(chan struct{})}
}

func (g *laneGate) wait() {
	if g != nil {
		g.pause.Do(func() {
			close(g.entered)
			<-g.release
		})
	}
}

func (g *laneGate) unblock() {
	if g != nil {
		g.resume.Do(func() { close(g.release) })
	}
}

type laneControls struct {
	commit      *laneGate
	rollback    *laneGate
	writeBegins atomic.Int64
	connections atomic.Int64
}

type controlledLaneConnector struct {
	driver.Connector
	controls *laneControls
}

type nativeLaneConnection interface {
	driver.Conn
	driver.ConnBeginTx
	driver.ConnPrepareContext
	driver.ExecerContext
	driver.QueryerContext
	driver.Pinger
	driver.SessionResetter
	driver.Validator
}

type controlledLaneConn struct {
	nativeLaneConnection
	controls *laneControls
}

func (c controlledLaneConnector) Connect(ctx context.Context) (driver.Conn, error) {
	conn, err := c.Connector.Connect(ctx)
	if err != nil {
		return nil, err
	}
	c.controls.connections.Add(1)
	return controlledLaneConn{conn.(nativeLaneConnection), c.controls}, nil
}

func (c controlledLaneConn) BeginTx(ctx context.Context, opts driver.TxOptions) (driver.Tx, error) {
	if !opts.ReadOnly {
		c.controls.writeBegins.Add(1)
	}
	tx, err := c.nativeLaneConnection.BeginTx(ctx, opts)
	if err != nil {
		return nil, err
	}
	return controlledLaneTx{Tx: tx, controls: c.controls, readOnly: opts.ReadOnly}, nil
}

type controlledLaneTx struct {
	driver.Tx
	controls *laneControls
	readOnly bool
}

func (tx controlledLaneTx) Commit() error {
	if !tx.readOnly {
		tx.controls.commit.wait()
	}
	return tx.Tx.Commit()
}

func (tx controlledLaneTx) Rollback() error {
	if !tx.readOnly {
		tx.controls.rollback.wait()
	}
	return tx.Tx.Rollback()
}

func newControlledLaneDB(t *testing.T, controls *laneControls) (*sql.DB, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "lanes.sqlite")
	query := url.Values{
		"_txlock": {"immediate"},
		"_pragma": {"foreign_keys(1)", "busy_timeout(5000)", "journal_mode(WAL)", "synchronous(FULL)"},
	}
	dsn := url.URL{Scheme: "file", Path: filepath.ToSlash(path), RawQuery: query.Encode()}
	connector, err := nativesqlite.NewConnector(dsn.String())
	if err != nil {
		t.Fatal(err)
	}
	db := openLaneDB(controlledLaneConnector{connector, controls})
	t.Cleanup(func() {
		controls.commit.unblock()
		controls.rollback.unblock()
		if err := db.Close(); err != nil {
			t.Error(err)
		}
	})
	if _, err := db.ExecContext(t.Context(), "CREATE TABLE lane_values (id INTEGER PRIMARY KEY, value TEXT NOT NULL); INSERT INTO lane_values VALUES (1, 'before')"); err != nil {
		t.Fatal(err)
	}
	return db, path
}

// Done tells the test that a waiter reached the cancellable admission path. The
// held writer/readers keep that path blocked until the test chooses an outcome.
type observedLaneContext struct {
	context.Context
	requested chan struct{}
	once      sync.Once
}

func (ctx *observedLaneContext) Done() <-chan struct{} {
	ctx.once.Do(func() { close(ctx.requested) })
	return ctx.Context.Done()
}

func waitLaneSignal(t *testing.T, signal <-chan struct{}, description string) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for %s", description)
	}
}

func waitLaneResult(t *testing.T, result <-chan error, description string) error {
	t.Helper()
	select {
	case err := <-result:
		return err
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for %s", description)
		return nil
	}
}

func laneValue(ctx context.Context, tx *sql.Tx) (string, error) {
	var value string
	err := tx.QueryRowContext(ctx, "SELECT value FROM lane_values WHERE id = 1").Scan(&value)
	return value, err
}

func TestWALLanesKeepSnapshotsIndependentOfCommitAndQueuedWriters(t *testing.T) {
	controls := &laneControls{commit: newLaneGate()}
	db, path := newControlledLaneDB(t, controls)
	statement, err := db.PrepareContext(t.Context(), "SELECT value FROM lane_values WHERE id = 1")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = statement.Close() })
	first := make(chan error, 1)
	go func() {
		first <- Transact(t.Context(), db, false, func(ctx context.Context, tx *sql.Tx) error {
			if _, err := tx.ExecContext(ctx, "UPDATE lane_values SET value = 'after' WHERE id = 1"); err != nil {
				return err
			}
			return Transact(ctx, db, true, func(ctx context.Context, borrowed *sql.Tx) error {
				if borrowed != tx {
					return errors.New("nested read did not borrow the owner's transaction")
				}
				var value string
				if err := borrowed.StmtContext(ctx, statement).QueryRowContext(ctx).Scan(&value); err != nil {
					return err
				}
				if value != "after" {
					return fmt.Errorf("nested read saw %q instead of the uncommitted write", value)
				}
				return nil
			})
		})
	}()
	waitLaneSignal(t, controls.commit.entered, "frozen writer commit")

	waiters, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	canceled := make(chan error, 2*(snapshotReaders+1))
	for range cap(canceled) {
		ctx := &observedLaneContext{Context: waiters, requested: make(chan struct{})}
		go func() {
			canceled <- Transact(ctx, db, false, func(context.Context, *sql.Tx) error {
				return errors.New("canceled writer callback ran")
			})
		}()
		waitLaneSignal(t, ctx.requested, "queued writer admission")
	}

	second := make(chan error, 1)
	secondContext := &observedLaneContext{Context: t.Context(), requested: make(chan struct{})}
	go func() {
		second <- Transact(secondContext, db, false, func(ctx context.Context, tx *sql.Tx) error {
			value, err := laneValue(ctx, tx)
			if err != nil {
				return err
			}
			if value != "after" {
				return fmt.Errorf("next writer saw %q before the previous commit", value)
			}
			_, err = tx.ExecContext(ctx, "UPDATE lane_values SET value = 'final' WHERE id = 1")
			return err
		})
	}()
	waitLaneSignal(t, secondContext.requested, "next serialized writer")

	readersReady := make(chan error, snapshotReaders)
	readersDone := make(chan error, snapshotReaders)
	releaseReaders := make(chan struct{})
	resumeReaders := sync.OnceFunc(func() { close(releaseReaders) })
	t.Cleanup(resumeReaders)
	for range snapshotReaders {
		go func() {
			readersDone <- Transact(t.Context(), db, true, func(ctx context.Context, tx *sql.Tx) error {
				value, err := laneValue(ctx, tx)
				if err == nil && value != "before" {
					err = fmt.Errorf("snapshot saw %q while writer commit was frozen", value)
				}
				readersReady <- err
				if err != nil {
					return err
				}
				<-releaseReaders
				value, err = laneValue(ctx, tx)
				if err == nil && value != "before" {
					err = fmt.Errorf("snapshot changed to %q after concurrent commits", value)
				}
				return err
			})
		}()
	}
	for range snapshotReaders {
		if err := waitLaneResult(t, readersReady, "independent WAL snapshot"); err != nil {
			t.Fatal(err)
		}
	}
	if stats := db.Stats(); stats.InUse != snapshotReaders+1 || stats.WaitCount != 0 {
		t.Fatalf("lane admission consumed connection capacity: %+v", stats)
	}

	readContext, cancelRead := context.WithCancel(t.Context())
	observedRead := &observedLaneContext{Context: readContext, requested: make(chan struct{})}
	extraRead := make(chan error, 1)
	go func() {
		extraRead <- Transact(observedRead, db, true, func(context.Context, *sql.Tx) error {
			return errors.New("reader exceeded bounded snapshot capacity")
		})
	}()
	waitLaneSignal(t, observedRead.requested, "bounded reader admission")
	cancelRead()
	if err := waitLaneResult(t, extraRead, "canceled excess reader"); !errors.Is(err, context.Canceled) {
		t.Fatalf("excess reader returned %v", err)
	}
	cancel()
	for range cap(canceled) {
		if err := waitLaneResult(t, canceled, "canceled queued writer"); !errors.Is(err, context.Canceled) {
			t.Fatalf("queued writer returned %v", err)
		}
	}
	if begins := controls.writeBegins.Load(); begins != 1 {
		t.Fatalf("queued writers reached native BeginTx: %d", begins)
	}
	if connections := controls.connections.Load(); connections != snapshotReaders+1 {
		t.Fatalf("canceled waiters opened connections: %d", connections)
	}
	if stats := db.Stats(); stats.WaitCount != 0 {
		t.Fatalf("waiters reached the connection pool instead of their lanes: %+v", stats)
	}
	controls.commit.unblock()
	if err := waitLaneResult(t, first, "first durable writer"); err != nil {
		t.Fatal(err)
	}
	if err := waitLaneResult(t, second, "serialized durable writer"); err != nil {
		t.Fatal(err)
	}
	resumeReaders()
	for range snapshotReaders {
		if err := waitLaneResult(t, readersDone, "completed stable snapshot"); err != nil {
			t.Fatal(err)
		}
	}
	oldOwner := db.Driver()
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(t.Context(), path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	if reopened.Driver() == oldOwner {
		t.Fatal("reopened database reused the closed lane owner")
	}
	if err := Transact(t.Context(), reopened, true, func(ctx context.Context, tx *sql.Tx) error {
		value, err := laneValue(ctx, tx)
		if err == nil && value != "final" {
			err = fmt.Errorf("reopened database retained %q instead of the durable final value", value)
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

func TestWALLanesCloseJoinsRollbackAndWakesWriters(t *testing.T) {
	controls := &laneControls{rollback: newLaneGate()}
	db, path := newControlledLaneDB(t, controls)
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	callbackReturned := make(chan struct{})
	ownerResult := make(chan error, 1)
	go func() {
		ownerResult <- Transact(ctx, db, false, func(ctx context.Context, tx *sql.Tx) error {
			defer close(callbackReturned)
			if _, err := tx.ExecContext(ctx, "UPDATE lane_values SET value = 'canceled' WHERE id = 1"); err != nil {
				return err
			}
			cancel()
			// Give database/sql's cancellation goroutine ownership of rollback.
			<-controls.rollback.entered
			return ctx.Err()
		})
	}()
	waitLaneSignal(t, callbackReturned, "callback returning during native rollback")
	owner := db.Driver().(*laneDriver)
	if len(owner.writer) != 1 {
		t.Fatal("writer permit returned while native rollback was blocked")
	}

	queuedContext := &observedLaneContext{Context: t.Context(), requested: make(chan struct{})}
	queuedResult := make(chan error, 1)
	go func() {
		queuedResult <- Transact(queuedContext, db, false, func(context.Context, *sql.Tx) error {
			return errors.New("writer ran before the canceled owner's rollback")
		})
	}()
	waitLaneSignal(t, queuedContext.requested, "writer queued behind native rollback")
	closed := make(chan error, 1)
	go func() { closed <- db.Close() }()
	waitLaneSignal(t, owner.done, "database closing admission")
	if err := waitLaneResult(t, queuedResult, "closed database waking queued writer"); !errors.Is(err, errDatabaseClosed) {
		t.Fatalf("queued writer on closing database returned %v", err)
	}
	select {
	case err := <-ownerResult:
		t.Fatalf("transaction returned before native rollback: %v", err)
	default:
	}
	select {
	case err := <-closed:
		t.Fatalf("Close returned before native rollback: %v", err)
	default:
	}
	if len(owner.writer) != 1 {
		t.Fatal("Close released the active writer permit before rollback")
	}
	controls.rollback.unblock()
	if err := waitLaneResult(t, ownerResult, "joined native rollback"); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled owner returned %v", err)
	}
	if err := waitLaneResult(t, closed, "joined database close"); err != nil {
		t.Fatal(err)
	}
	if len(owner.writer) != 0 {
		t.Fatal("completed rollback retained its writer permit")
	}
	if err := Transact(t.Context(), db, false, func(context.Context, *sql.Tx) error {
		return errors.New("callback ran on closed database")
	}); !errors.Is(err, errDatabaseClosed) {
		t.Fatalf("transaction after Close returned %v", err)
	}
	reopened, err := Open(t.Context(), path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	if err := Transact(t.Context(), reopened, true, func(ctx context.Context, tx *sql.Tx) error {
		value, err := laneValue(ctx, tx)
		if err == nil && value != "before" {
			err = fmt.Errorf("reopened database retained rolled-back value %q", value)
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
}
