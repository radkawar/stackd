package backends_test

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	moderncsqlite "modernc.org/sqlite"

	"stackd/storage/iam"
	"stackd/storage/s3"
	"stackd/storage/sqlite"
	"stackd/storage/sqlite/backends"
	sqliam "stackd/storage/sqlite/iam"
	sqls3 "stackd/storage/sqlite/s3"
)

type observedSQLiteConnection interface {
	driver.Conn
	driver.ConnBeginTx
	driver.ConnPrepareContext
	driver.ExecerContext
	driver.QueryerContext
	driver.Pinger
	driver.SessionResetter
	driver.Validator
}

// Only observations are intercepted. Every statement, transaction, result and
// cancellation below executes in the real modernc SQLite connection.
type preparationCounts struct {
	prepared atomic.Int64
	oneShot  atomic.Int64
	queries  sync.Map
}

type observedSQLiteConnector struct {
	driver.Connector
	counts *preparationCounts
}

func (c observedSQLiteConnector) Connect(ctx context.Context) (driver.Conn, error) {
	native, err := c.Connector.Connect(ctx)
	if err != nil {
		return nil, err
	}
	return &countedSQLiteConnection{observedSQLiteConnection: native.(observedSQLiteConnection), counts: c.counts}, nil
}

type countedSQLiteConnection struct {
	observedSQLiteConnection
	counts *preparationCounts
}

func (c *countedSQLiteConnection) PrepareContext(ctx context.Context, query string) (driver.Stmt, error) {
	c.counts.prepared.Add(1)
	c.counts.queries.Store(query, struct{}{})
	return c.observedSQLiteConnection.PrepareContext(ctx, query)
}

func (c *countedSQLiteConnection) ExecContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	c.counts.oneShot.Add(1)
	return c.observedSQLiteConnection.ExecContext(ctx, query, args)
}

func (c *countedSQLiteConnection) QueryContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	c.counts.oneShot.Add(1)
	return c.observedSQLiteConnection.QueryContext(ctx, query, args)
}

func observedSQLite(t *testing.T) (*sql.DB, *preparationCounts) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "prepared.sqlite")
	initial, err := sqlite.Open(t.Context(), path)
	if err != nil {
		t.Fatal(err)
	}
	if err := initial.Close(); err != nil {
		t.Fatal(err)
	}
	connector, err := moderncsqlite.NewConnector(path + "?_txlock=immediate&_pragma=foreign_keys(1)&_pragma=journal_mode(WAL)&_pragma=synchronous(FULL)")
	if err != nil {
		t.Fatal(err)
	}
	counts := &preparationCounts{}
	db := sql.OpenDB(observedSQLiteConnector{connector, counts})
	db.SetMaxOpenConns(1)
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Error(err)
		}
	})
	return db, counts
}

func TestHotRepositoriesReusePreparedQueriesAcrossTransactions(t *testing.T) {
	db, counts := observedSQLite(t)
	stores, err := backends.New(t.Context(), db)
	if err != nil {
		t.Fatal(err)
	}
	prepared := counts.prepared.Load()
	oneShot := counts.oneShot.Load()
	if prepared == 0 {
		t.Fatal("constructors did not prepare service queries")
	}
	scope := iam.Scope{Partition: "aws", AccountID: "123456789012"}
	created := time.Unix(1, 0).UTC()
	const workers = 8
	var work sync.WaitGroup
	failures := make(chan error, workers)
	for index := range workers {
		work.Go(func() {
			name := fmt.Sprintf("prepared-%d", index)
			user := iam.User{UserName: name, UserId: "AIDA" + name, Arn: "arn:aws:iam::123456789012:user/" + name, Path: "/", CreateDate: created}
			bucket := s3.BucketRecord{Key: s3.BucketKey{Partition: "aws", Name: name}, AccountID: scope.AccountID, Region: "us-east-1", Created: created}
			if err := stores.IAM.Update(t.Context(), func(tx iam.WriteTx) error { return tx.PutUser(scope, user) }); err != nil {
				failures <- err
				return
			}
			if err := stores.S3.Update(t.Context(), func(tx s3.Transaction) error { return tx.PutBucket(bucket) }); err != nil {
				failures <- err
				return
			}
			for range 3 {
				if err := stores.Read(t.Context(), func(ctx context.Context) error {
					if err := stores.IAM.View(ctx, func(tx iam.ReadTx) error {
						got, err := tx.User(scope, name)
						if err == nil && got.UserId != user.UserId {
							return errors.New("reused IAM statement leaked another caller's bindings")
						}
						return err
					}); err != nil {
						return err
					}
					return stores.S3.View(ctx, func(tx s3.Reader) error {
						got, err := tx.Bucket(bucket.Key)
						if err == nil && got.Key != bucket.Key {
							return errors.New("reused S3 statement leaked another caller's bindings")
						}
						return err
					})
				}); err != nil {
					failures <- err
					return
				}
			}
		})
	}
	work.Wait()
	close(failures)
	for err := range failures {
		t.Error(err)
	}
	if got := counts.prepared.Load(); got != prepared {
		t.Fatalf("repository callbacks re-prepared SQL: before=%d after=%d", prepared, got)
	}
	if got := counts.oneShot.Load(); got != oneShot {
		t.Fatalf("repository callbacks executed one-shot SQL: before=%d after=%d", oneShot, got)
	}
	// Native commit configuration is unchanged by retaining compiled SQL.
	var synchronous int
	if err := db.QueryRowContext(t.Context(), "PRAGMA synchronous").Scan(&synchronous); err != nil || synchronous != 2 {
		t.Fatalf("FULL synchronization=%d: %v", synchronous, err)
	}
	rejected := errors.New("reject atomic joined write")
	err = stores.IAM.Update(t.Context(), func(tx iam.WriteTx) error {
		if err := tx.PutUser(scope, iam.User{UserName: "rolled-back", UserId: "AIDAROLLBACK", Arn: "arn:aws:iam::123456789012:user/rolled-back", Path: "/", CreateDate: created}); err != nil {
			return err
		}
		if err := stores.S3.Update(tx.Context(), func(tx s3.Transaction) error {
			return tx.PutBucket(s3.BucketRecord{Key: s3.BucketKey{Partition: "aws", Name: "rolled-back"}, AccountID: scope.AccountID, Region: "us-east-1", Created: created})
		}); err != nil {
			return err
		}
		return rejected
	})
	if !errors.Is(err, rejected) {
		t.Fatalf("joined rollback=%v", err)
	}
	if err := stores.IAM.View(t.Context(), func(tx iam.ReadTx) error { _, err := tx.User(scope, "rolled-back"); return err }); !errors.Is(err, iam.ErrRecordNotFound) {
		t.Fatalf("IAM row survived rollback: %v", err)
	}
	if err := stores.S3.View(t.Context(), func(tx s3.Reader) error {
		_, err := tx.Bucket(s3.BucketKey{Partition: "aws", Name: "rolled-back"})
		return err
	}); !errors.Is(err, s3.ErrNotFound) {
		t.Fatalf("S3 row survived joined rollback: %v", err)
	}
}

func TestHotRepositoryPreparationReturnsSchemaErrors(t *testing.T) {
	// Missing tables must fail at construction, not in a later request or by
	// silently falling back to one-shot SQL inside a borrowed transaction.
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "empty.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if repository, err := sqliam.New(t.Context(), db); err == nil || repository != nil {
		t.Fatalf("IAM constructor accepted missing schema: %v %v", repository, err)
	}
	if repository, err := sqls3.New(t.Context(), db); err == nil || repository != nil {
		t.Fatalf("S3 constructor accepted missing schema: %v %v", repository, err)
	}
}

func TestHotRepositoriesPreparedAttemptBoundaries(t *testing.T) {
	for _, repository := range []string{"iam", "s3"} {
		for _, boundary := range []string{"rejection", "cancellation"} {
			t.Run(repository+"/"+boundary, func(t *testing.T) {
				db, _ := observedSQLite(t)
				stores, err := backends.New(t.Context(), db)
				if err != nil {
					t.Fatal(err)
				}
				scope := iam.Scope{Partition: "aws", AccountID: "123456789012"}
				created := time.Unix(1, 0).UTC()
				user := func(name string) iam.User {
					return iam.User{UserName: name, UserId: "AIDA" + name, Arn: "arn:aws:iam::123456789012:user/" + name, Path: "/", CreateDate: created}
				}
				bucket := s3.BucketRecord{Key: s3.BucketKey{Partition: "aws", Name: "attempted"}, AccountID: scope.AccountID, Region: "us-east-1", Created: created}
				rejected := errors.New("reject prepared command")
				err = stores.IAM.Update(t.Context(), func(owner iam.WriteTx) error {
					ctx, cancel := context.WithCancel(owner.Context())
					defer cancel()
					command := func(ctx context.Context) error {
						if err := stores.IAM.Update(ctx, func(tx iam.WriteTx) error { return tx.PutUser(scope, user("attempted")) }); err != nil {
							return err
						}
						if err := stores.S3.Update(ctx, func(tx s3.Transaction) error { return tx.PutBucket(bucket) }); err != nil {
							return err
						}
						if boundary == "cancellation" {
							cancel()
							return nil
						}
						return rejected
					}
					var attemptErr error
					if repository == "iam" {
						attemptErr = stores.IAM.Attempt(ctx, func(tx iam.WriteTx) error { return command(tx.Context()) })
					} else {
						attemptErr = stores.S3.Attempt(ctx, func(tx s3.Transaction) error { return command(tx.Context()) })
					}
					want := rejected
					if boundary == "cancellation" {
						want = context.Canceled
					}
					if !errors.Is(attemptErr, want) {
						t.Fatalf("prepared attempt error = %v, want %v", attemptErr, want)
					}
					if _, err := owner.User(scope, "attempted"); !errors.Is(err, iam.ErrRecordNotFound) {
						t.Fatalf("IAM command write survived savepoint rollback: %v", err)
					}
					if err := stores.S3.View(owner.Context(), func(tx s3.Reader) error {
						_, err := tx.Bucket(bucket.Key)
						return err
					}); !errors.Is(err, s3.ErrNotFound) {
						t.Fatalf("S3 command write survived savepoint rollback: %v", err)
					}
					// Reuse the same prepared query after savepoint cleanup. The
					// failed command must not cancel or poison its owner.
					return owner.PutUser(scope, user("retained"))
				})
				if err != nil {
					t.Fatal(err)
				}
				if err := stores.IAM.View(t.Context(), func(tx iam.ReadTx) error {
					_, err := tx.User(scope, "retained")
					return err
				}); err != nil {
					t.Fatalf("outer command did not commit after failed attempt: %v", err)
				}
			})
		}
	}
}
