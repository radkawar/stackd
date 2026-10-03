package sqlite_test

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"

	nativesqlite "modernc.org/sqlite"

	"stackd/internal/awstest"
	"stackd/journal"
	"stackd/storage/sqlite"
	sqljournal "stackd/storage/sqlite/journal"
	sqlsqs "stackd/storage/sqlite/sqs"
	"stackd/storage/sqs"
)

func TestWaitingTransactionHonorsCancellation(t *testing.T) {
	db, err := sqlite.Open(t.Context(), filepath.Join(t.TempDir(), "state.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	first, err := db.BeginTx(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Rollback()
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Millisecond)
	defer cancel()
	called := false
	err = sqlite.Transact(ctx, db, false, func(context.Context, *sql.Tx) error { called = true; return nil })
	if !errors.Is(err, context.DeadlineExceeded) || called {
		t.Fatalf("waiting transaction=%v, callback called=%v", err, called)
	}
}

func TestMigrationRetainsVersionOneQueueState(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.sqlite")
	db, err := sqlite.Open(t.Context(), path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	key := sqs.QueueKey{Partition: "aws", Account: "111111111111", Region: "us-east-1", Name: "retained"}
	if err := sqlsqs.New(db).Update(t.Context(), func(tx sqs.Transaction) error {
		if err := tx.PutQueue(sqs.QueueRecord{Key: key, ID: "queue"}); err != nil {
			return err
		}
		return tx.PutMessages("queue", sqs.QueueMessages{Messages: []sqs.MessageRecord{{ID: "message", Data: []byte("retained payload")}}})
	}); err != nil {
		t.Fatal(err)
	}
	current := path
	path = filepath.Join(t.TempDir(), "version1.sqlite")
	historical := awstest.HistoricalSQLite(t, path, "schema", 1, current, nil)
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if err := historical.Close(); err != nil {
		t.Fatal(err)
	}
	db, err = sqlite.Open(t.Context(), path)
	if err != nil {
		t.Fatal(err)
	}
	if err := sqlsqs.New(db).View(t.Context(), func(reader sqs.Reader) error {
		queue, err := reader.Queue(key)
		if err != nil {
			return err
		}
		messages, err := reader.Messages(queue.ID)
		if err != nil {
			return err
		}
		if len(messages.Messages) != 1 || string(messages.Messages[0].Data) != "retained payload" {
			t.Fatal("migration lost queued data")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestSchemaOpenRejectsNewerDatabaseWithoutChangingState(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state?version.sqlite")
	db, err := sqlite.Open(t.Context(), path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := db.ExecContext(t.Context(), "PRAGMA user_version = 100000"); err != nil {
		t.Fatal(err)
	}
	if opened, err := sqlite.Open(t.Context(), path); err == nil {
		_ = opened.Close()
		t.Fatal("older implementation accepted a newer schema")
	}
	var version int
	if err := db.QueryRowContext(t.Context(), "PRAGMA user_version").Scan(&version); err != nil {
		t.Fatal(err)
	}
	if version != 100000 {
		t.Fatal("opening an unsupported schema changed its version", version)
	}
}

func TestMigrationRetainsVersionSevenSessionHistory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.sqlite")
	db := awstest.HistoricalSQLite(t, path, "schema", 7, "", nil)
	epoch := time.Date(2031, 2, 3, 4, 5, 6, 123456789, time.UTC)
	envelope := journal.Envelope{At: epoch, Partition: "aws", AccountID: "111111111111", Region: "us-east-1", RequestID: "original-request", ActorARN: "arn:aws:iam::111111111111:root"}
	session := journal.SessionIssued{PrincipalARN: envelope.ActorARN, SessionType: "GetSessionToken", Expiration: epoch.Add(time.Hour)}
	// Seed the actual schema-7 columns. Today's journal adapter belongs after upgrade.
	if _, err := db.ExecContext(t.Context(), `INSERT INTO kernel_events
		(sequence,occurred_at,partition,account_id,region,request_id,actor_arn,event_type)
		VALUES(1,?,?,?,?,?,?, 'sts.session.issued.v1')`, epoch, envelope.Partition, envelope.AccountID, envelope.Region, envelope.RequestID, envelope.ActorARN); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(t.Context(), `INSERT INTO iam_session_events
		(sequence,principal_arn,issuer_arn,session_type,expiration) VALUES(1,?,?,?,?)`, session.PrincipalARN, session.IssuerARN, session.SessionType, session.Expiration); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	db, err := sqlite.Open(t.Context(), path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	history := sqljournal.New(db)
	change := journal.AccessKeyChanged{Action: journal.AccessKeyCreated, AccessKeyID: "AKIAEXAMPLE0000000000", PrincipalARN: envelope.ActorARN, Status: "Active"}
	if err := history.AppendAccessKeyChanged(t.Context(), envelope, change); err != nil {
		t.Fatal(err)
	}
	first, second := envelope, envelope
	first.Sequence, second.Sequence = 1, 2
	want := []journal.Event{{Envelope: first, SessionIssued: session}, {Envelope: second, AccessKeyChanged: change}}
	rows, err := history.Read(t.Context(), 0, 100)
	if err != nil || !reflect.DeepEqual(rows, want) {
		t.Fatal("migration lost session history or did not continue with access-key events", rows, err)
	}
}

type rollbackConnector struct {
	driver.Connector
	entered chan struct{}
	release <-chan struct{}
}

type rollbackConnection interface {
	driver.Conn
	driver.ConnBeginTx
	driver.SessionResetter
	driver.Validator
}

type rollbackConn struct {
	rollbackConnection
	entered chan struct{}
	release <-chan struct{}
}

func (c rollbackConnector) Connect(ctx context.Context) (driver.Conn, error) {
	conn, err := c.Connector.Connect(ctx)
	if err != nil {
		return nil, err
	}
	return rollbackConn{conn.(rollbackConnection), c.entered, c.release}, nil
}

func (c rollbackConn) BeginTx(ctx context.Context, opts driver.TxOptions) (driver.Tx, error) {
	tx, err := c.rollbackConnection.BeginTx(ctx, opts)
	if err != nil {
		return nil, err
	}
	return rollbackTx{tx, c.entered, c.release}, nil
}

type rollbackTx struct {
	driver.Tx
	entered chan struct{}
	release <-chan struct{}
}

func (tx rollbackTx) Rollback() error {
	close(tx.entered)
	<-tx.release
	return tx.Tx.Rollback()
}

func TestCanceledTransactionJoinsRollbackBeforeClose(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rollback.sqlite")
	dsn := path + "?_pragma=journal_mode(WAL)"
	connector, err := nativesqlite.NewConnector(dsn)
	if err != nil {
		t.Fatal(err)
	}
	entered, release := make(chan struct{}), make(chan struct{})
	resume := sync.OnceFunc(func() { close(release) })
	db := sql.OpenDB(rollbackConnector{connector, entered, release})
	db.SetMaxOpenConns(1)
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Error(err)
		}
	})
	if _, err := db.ExecContext(t.Context(), "CREATE TABLE writes (value TEXT)"); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	callbackReturned := make(chan struct{})
	result, finished := make(chan error, 1), make(chan struct{})
	go func() {
		defer close(finished)
		result <- sqlite.Transact(ctx, db, false, func(ctx context.Context, tx *sql.Tx) error {
			defer close(callbackReturned)
			if _, err := tx.ExecContext(ctx, "INSERT INTO writes VALUES ('canceled')"); err != nil {
				return err
			}
			cancel()
			// Let database/sql's cancellation goroutine own the rollback
			// before the callback returns and Transact calls Rollback itself.
			<-entered
			return ctx.Err()
		})
	}()
	defer func() {
		resume()
		<-finished
	}()
	select {
	case <-callbackReturned:
	case <-time.After(5 * time.Second):
		t.Fatal("canceled transaction did not reach rollback")
	}
	select {
	case err := <-result:
		t.Fatalf("transaction returned before native rollback completed: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	resume()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled transaction returned %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("transaction did not join completed rollback")
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	db, err = sql.Open("sqlite", dsn)
	if err != nil {
		t.Fatal(err)
	}
	var writes int
	if err := db.QueryRowContext(t.Context(), "SELECT count(*) FROM writes").Scan(&writes); err != nil {
		t.Fatal(err)
	}
	if writes != 0 {
		t.Fatalf("canceled write survived database close and reopen: %d", writes)
	}
}
