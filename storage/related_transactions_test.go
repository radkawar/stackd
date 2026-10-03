package storage_test

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"stackd/storage"
	"stackd/storage/cloudwatch"
	"stackd/storage/kms"
	"stackd/storage/sqlite"
	sqlbackends "stackd/storage/sqlite/backends"
	sqlkms "stackd/storage/sqlite/kms"
	sqlsqs "stackd/storage/sqlite/sqs"
	"stackd/storage/sqs"
)

func forRelatedRepositories(t *testing.T, run func(*testing.T, kms.Storage, sqs.Repository)) {
	t.Helper()
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			if backend == "memory" {
				backends := storage.NewMemory()
				run(t, backends.KMS, backends.SQS)
				return
			}
			db, err := sqlite.Open(t.Context(), filepath.Join(t.TempDir(), "state.sqlite"))
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			run(t, sqlkms.New(db), sqlsqs.New(db))
		})
	}
}

func TestRelatedRepositoriesCommitAndExpireTogether(t *testing.T) {
	forRelatedRepositories(t, testRelatedRepositoriesCommitAndExpireTogether)
}

func testRelatedRepositoriesCommitAndExpireTogether(t *testing.T, keys kms.Storage, queues sqs.Repository) {
	owner := kms.KeyOwner{Partition: "aws", AccountID: "111111111111"}
	queue := sqs.QueueRecord{Key: sqs.QueueKey{Partition: "aws", Account: owner.AccountID, Region: "us-east-1", Name: "joined"}, ID: "queue"}
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	var nested sqs.Transaction
	var outer context.Context
	if err := keys.Transact(ctx, func(tx kms.Transaction) error {
		outer = tx.Context()
		if err := tx.PutKeySet(owner, kms.KeySetRecord{ID: "key", Materials: []kms.KeyMaterialRecord{{ID: "material", Material: []byte{1, 2, 3}}}}); err != nil {
			return err
		}
		if err := queues.Update(tx.Context(), func(writer sqs.Transaction) error {
			nested = writer
			if err := writer.PutQueue(queue); err != nil {
				return err
			}
			return keys.Transact(writer.Context(), func(reader kms.Transaction) error {
				set, err := reader.KeySet(owner, "key")
				if err == nil && len(set.Materials) != 1 {
					t.Error("nested repository missed staged key material")
				}
				return err
			})
		}); err != nil {
			return err
		}
		if _, err := nested.Queue(queue.Key); err == nil {
			t.Fatal("nested callback retained a usable reader")
		}
		// The nested callback has expired, but the owner's snapshot is alive.
		return queues.View(tx.Context(), func(reader sqs.Reader) error {
			_, err := reader.Queue(queue.Key)
			return err
		})
	}); err != nil {
		t.Fatal(err)
	}
	if !errors.Is(outer.Err(), context.Canceled) {
		t.Fatal("owner context did not expire", outer.Err())
	}
	if err := queues.Update(outer, func(sqs.Transaction) error { t.Fatal("escaped context started a new callback"); return nil }); err == nil {
		t.Fatal("escaped transaction context was accepted")
	}
	if err := queues.View(ctx, func(reader sqs.Reader) error {
		_, err := reader.Queue(queue.Key)
		return err
	}); err != nil {
		t.Fatal("related queue was not committed", err)
	}
}

func TestFailedNestedWritesAbortTheTransaction(t *testing.T) {
	forRelatedRepositories(t, testFailedNestedWritesAbortTheTransaction)
}

func testFailedNestedWritesAbortTheTransaction(t *testing.T, keys kms.Storage, queues sqs.Repository) {
	for _, mode := range []string{"error", "panic", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			owner := kms.KeyOwner{Partition: "aws", AccountID: "111111111111"}
			queue := sqs.QueueRecord{Key: sqs.QueueKey{Partition: "aws", Account: owner.AccountID, Region: "us-east-1", Name: "aborted"}, ID: "queue"}
			ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
			defer cancel()
			err := keys.Transact(ctx, func(tx kms.Transaction) error {
				if err := tx.PutKeySet(owner, kms.KeySetRecord{ID: "key"}); err != nil {
					return err
				}
				func() {
					defer func() { _ = recover() }()
					nestedCtx, cancel := context.WithCancel(tx.Context())
					defer cancel()
					_ = queues.Update(nestedCtx, func(writer sqs.Transaction) error {
						if err := writer.PutQueue(queue); err != nil {
							return err
						}
						switch mode {
						case "error":
							return errors.New("nested write failed")
						case "panic":
							panic("nested write failed")
						case "cancel":
							cancel()
						}
						return nil
					})
				}()
				return nil // Catching the failure must not permit a partial commit.
			})
			if err == nil {
				t.Fatal("owner committed after a failed nested write")
			}
			if err := keys.Transact(t.Context(), func(tx kms.Transaction) error {
				if _, err := tx.KeySet(owner, "key"); !errors.Is(err, kms.ErrKeySetNotFound) {
					t.Fatal("aborted key remains", err)
				}
				return queues.View(tx.Context(), func(reader sqs.Reader) error {
					if _, err := reader.Queue(queue.Key); !errors.Is(err, sqs.ErrNotFound) {
						t.Fatal("aborted queue remains", err)
					}
					return nil
				})
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestRelatedReadCannotAcquireAWriter(t *testing.T) {
	forRelatedRepositories(t, testRelatedReadCannotAcquireAWriter)
}

func testRelatedReadCannotAcquireAWriter(t *testing.T, keys kms.Storage, queues sqs.Repository) {
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	if err := queues.View(ctx, func(reader sqs.Reader) error {
		err := keys.Transact(reader.Context(), func(kms.Transaction) error { t.Fatal("read-only callback acquired a writer"); return nil })
		if err == nil || errors.Is(err, context.DeadlineExceeded) {
			t.Fatal("write upgrade was not rejected at the owning transaction", err)
		}
		_, err = reader.Queues()
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

func TestCommandSavepointsPreserveOuterAtomicity(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			var backends *storage.Backends
			if backend == "memory" {
				backends = storage.NewMemory()
			} else {
				db, err := sqlite.Open(t.Context(), filepath.Join(t.TempDir(), "commands.sqlite"))
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() {
					if err := db.Close(); err != nil {
						t.Error(err)
					}
				})
				backends, err = sqlbackends.New(t.Context(), db)
				if err != nil {
					t.Fatal(err)
				}
			}
			keys, queues, commands := backends.KMS, backends.SQS, backends.CloudWatch
			owner := kms.KeyOwner{Partition: "aws", AccountID: "111111111111"}
			queueKey := func(name string) sqs.QueueKey {
				return sqs.QueueKey{Partition: owner.Partition, Account: owner.AccountID, Region: "us-east-1", Name: name}
			}
			keySet := func(marker string) kms.KeySetRecord {
				return kms.KeySetRecord{ID: "key", Materials: []kms.KeyMaterialRecord{{ID: marker, Material: []byte(marker)}}}
			}
			boom := errors.New("rejected command")
			write := func(ctx context.Context, marker string, reject bool) error {
				if err := keys.Transact(ctx, func(tx kms.Transaction) error { return tx.PutKeySet(owner, keySet(marker)) }); err != nil {
					return err
				}
				err := queues.Update(ctx, func(tx sqs.Transaction) error {
					if err := tx.PutQueue(sqs.QueueRecord{Key: queueKey(marker), ID: marker}); err != nil {
						return err
					}
					if reject {
						return boom
					}
					return nil
				})
				if reject && errors.Is(err, boom) {
					return nil
				} // A caught nested write still rejects this command.
				return err
			}
			if err := keys.Transact(t.Context(), func(outer kms.Transaction) error {
				if err := outer.PutKeySet(owner, keySet("before")); err != nil {
					return err
				}
				err := commands.Attempt(outer.Context(), func(tx cloudwatch.Transaction) error { return write(tx.Context(), "rejected", true) })
				if !errors.Is(err, boom) {
					t.Fatalf("command rejection: %v", err)
				}
				before, err := outer.KeySet(owner, "key")
				if err != nil || len(before.Materials) != 1 || before.Materials[0].ID != "before" {
					t.Fatalf("rejected command changed parent state: %+v %v", before, err)
				}
				if err := commands.Attempt(outer.Context(), func(tx cloudwatch.Transaction) error { return write(tx.Context(), "accepted", false) }); err != nil {
					return err
				}
				accepted, err := outer.KeySet(owner, "key")
				if err != nil || len(accepted.Materials) != 1 || accepted.Materials[0].ID != "accepted" {
					t.Fatalf("parent reader missed accepted child state: %+v %v", accepted, err)
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			// A successful savepoint is not an independent commit.
			err := keys.Transact(t.Context(), func(outer kms.Transaction) error {
				if err := commands.Attempt(outer.Context(), func(tx cloudwatch.Transaction) error { return write(tx.Context(), "owner-rollback", false) }); err != nil {
					return err
				}
				return boom
			})
			if !errors.Is(err, boom) {
				t.Fatal(err)
			}
			if err := keys.Transact(t.Context(), func(tx kms.Transaction) error {
				retained, err := tx.KeySet(owner, "key")
				if err != nil || len(retained.Materials) != 1 || retained.Materials[0].ID != "accepted" {
					t.Fatalf("owner rollback leaked child state: %+v %v", retained, err)
				}
				return queues.View(tx.Context(), func(reader sqs.Reader) error {
					if _, err := reader.Queue(queueKey("accepted")); err != nil {
						return err
					}
					for _, name := range []string{"rejected", "owner-rollback"} {
						if _, err := reader.Queue(queueKey(name)); !errors.Is(err, sqs.ErrNotFound) {
							t.Fatalf("%s queue escaped rollback: %v", name, err)
						}
					}
					return nil
				})
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}
