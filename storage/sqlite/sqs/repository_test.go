package sqs_test

import (
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"stackd/storage/sqlite"
	backend "stackd/storage/sqlite/sqs"
	"stackd/storage/sqs"
)

func TestSQLiteQueueDeletionRetainsIndependentLifecycles(t *testing.T) {
	db, err := sqlite.Open(t.Context(), filepath.Join(t.TempDir(), "state.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	repo := backend.New(db)
	at := time.Date(2030, 4, 5, 6, 7, 8, 0, time.UTC)
	key := sqs.QueueKey{Partition: "aws", Account: "111111111111", Region: "us-east-1", Name: "retained"}
	queue := sqs.QueueRecord{Key: key, ID: "queue"}
	messages := sqs.QueueMessages{
		Messages:       []sqs.MessageRecord{{ID: "message"}},
		Receipts:       []sqs.ReceiptRecord{{Handle: "receipt", MessageID: "message"}},
		Deduplications: []sqs.DeduplicationRecord{{Token: "token", MessageID: "message"}},
		Attempts:       []sqs.ReceiveAttemptRecord{{Token: "attempt", MessageIDs: []string{"message"}, Handles: []string{"receipt"}, Generations: []uint64{1}}},
		NoisyGroups:    []sqs.NoisyGroupRecord{{Group: "group"}},
	}
	task := sqs.MoveTaskRecord{Handle: "task", Source: key, SourceID: queue.ID, Status: "RUNNING", Started: at, Due: at.Add(time.Second)}
	if err := repo.Update(t.Context(), func(tx sqs.Transaction) error {
		if err := tx.PutQueue(queue); err != nil {
			return err
		}
		if err := tx.PutMessages(queue.ID, messages); err != nil {
			return err
		}
		return tx.PutMoveTask(task)
	}); err != nil {
		t.Fatal(err)
	}
	if err := repo.Update(t.Context(), func(tx sqs.Transaction) error {
		if err := tx.DeleteQueue(key); err != nil {
			return err
		}
		return tx.SetDeletedAt(key, at)
	}); err != nil {
		t.Fatal(err)
	}
	if err := repo.View(t.Context(), func(reader sqs.Reader) error {
		if _, err := reader.Queue(key); !errors.Is(err, sqs.ErrNotFound) {
			t.Fatalf("deleted queue remains: %v", err)
		}
		delivery, err := reader.Messages(queue.ID)
		if err != nil {
			return err
		}
		if !reflect.DeepEqual(delivery, sqs.QueueMessages{}) {
			t.Fatalf("queue deletion retained delivery state: %+v", delivery)
		}
		tasks, err := reader.MoveTasks()
		if err != nil {
			return err
		}
		if len(tasks) != 1 || tasks[0].Handle != task.Handle || tasks[0].Status != "RUNNING" {
			t.Fatalf("queue deletion removed independently scheduled move work: %+v", tasks)
		}
		deleted, err := reader.DeletedAt(key)
		if err == nil && !deleted.Equal(at) {
			t.Fatalf("queue deletion lost its recreation-delay tombstone: %v", deleted)
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

func TestSQLiteFailedDeliveryCommitRollsBackAndExpiresHandles(t *testing.T) {
	db, err := sqlite.Open(t.Context(), filepath.Join(t.TempDir(), "state.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	repo := backend.New(db)
	queue := sqs.QueueRecord{Key: sqs.QueueKey{Partition: "aws", Account: "111111111111", Region: "us-east-1", Name: "q"}, ID: "queue"}
	var escaped sqs.Transaction
	if err := repo.Update(t.Context(), func(tx sqs.Transaction) error { escaped = tx; return tx.PutQueue(queue) }); err != nil {
		t.Fatal(err)
	}
	if err := escaped.PutQueue(queue); err == nil {
		t.Fatal("escaped transaction remains usable", err)
	}
	for _, mode := range []string{"error", "cancel", "constraint", "panic"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			write := func() error {
				return repo.Update(ctx, func(tx sqs.Transaction) error {
					if err := tx.PutMessages(queue.ID, sqs.QueueMessages{Messages: []sqs.MessageRecord{{ID: "new"}}}); err != nil {
						return err
					}
					switch mode {
					case "error":
						return errors.New("abort")
					case "cancel":
						cancel()
					case "constraint":
						return tx.PutMessages("missing-queue", sqs.QueueMessages{Messages: []sqs.MessageRecord{{ID: "orphan"}}})
					case "panic":
						panic("abort")
					}
					return nil
				})
			}
			if mode == "panic" {
				func() {
					defer func() {
						if recover() == nil {
							t.Error("transaction swallowed panic")
						}
					}()
					_ = write()
				}()
			} else if err := write(); err == nil {
				t.Fatal("failed transaction committed")
			}
			if err := repo.View(t.Context(), func(reader sqs.Reader) error {
				messages, err := reader.Messages(queue.ID)
				if len(messages.Messages) != 0 {
					t.Error("failed transaction published messages")
				}
				return err
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}
