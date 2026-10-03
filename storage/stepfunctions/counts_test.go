package stepfunctions_test

import (
	"errors"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"stackd/storage/sqlite"
	sqlstepfunctions "stackd/storage/sqlite/stepfunctions"
	"stackd/storage/stepfunctions"
)

func TestResourceCountsFollowScopedTransactionalState(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			var repo stepfunctions.Repository
			if backend == "memory" {
				repo = stepfunctions.NewMemory(nil)
			} else {
				db, err := sqlite.Open(t.Context(), filepath.Join(t.TempDir(), "counts.sqlite"))
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() {
					if err := db.Close(); err != nil {
						t.Error(err)
					}
				})
				repo, err = sqlstepfunctions.New(t.Context(), db)
				if err != nil {
					t.Fatal(err)
				}
			}
			scopes := []stepfunctions.Scope{
				{Partition: "aws", AccountID: "111111111111", Region: "us-east-1"},
				{Partition: "aws-cn", AccountID: "111111111111", Region: "us-east-1"},
				{Partition: "aws", AccountID: "222222222222", Region: "us-east-1"},
				{Partition: "aws", AccountID: "111111111111", Region: "us-west-2"},
			}
			scope := scopes[0]
			now := time.Date(2026, 9, 24, 0, 0, 0, 0, time.UTC)
			machine := stepfunctions.MachineRecord{Key: stepfunctions.MachineKey{Scope: scope, Name: "deleting"}, ID: "deleting", RevisionID: "revision", Type: "STANDARD", Status: "DELETING", Created: now, DeleteAt: &now}
			execution := func(s stepfunctions.Scope, name, kind, status string) stepfunctions.ExecutionRecord {
				return stepfunctions.ExecutionRecord{Key: stepfunctions.ExecutionKey{Scope: s, ARN: name}, Machine: stepfunctions.MachineKey{Scope: s, Name: "machine"}, MachineID: "machine", RevisionID: "revision", Name: name, Type: kind, Status: status, Started: now, Deadline: now.Add(time.Hour)}
			}
			check := func(r stepfunctions.Reader, s stepfunctions.Scope, want [3]int64) error {
				var got [3]int64
				var err error
				if got[0], err = r.MachineCount(s); err != nil {
					return err
				}
				if got[1], err = r.ActivityCount(s); err != nil {
					return err
				}
				if got[2], err = r.OpenExecutionCount(s); err != nil {
					return err
				}
				if got != want {
					return fmt.Errorf("scope %+v: machine/activity/open counts = %v, want %v", s, got, want)
				}
				return nil
			}
			if err := repo.Update(t.Context(), func(tx stepfunctions.Transaction) error {
				for _, s := range scopes {
					if err := check(tx, s, [3]int64{}); err != nil {
						return err
					}
					key := stepfunctions.MachineKey{Scope: s, Name: "machine"}
					if err := tx.PutRevision(stepfunctions.RevisionRecord{Key: stepfunctions.RevisionKey{Scope: s, ID: "revision"}, Machine: key, MachineID: "machine", Created: now}); err != nil {
						return err
					}
					if err := tx.PutMachine(stepfunctions.MachineRecord{Key: key, ID: "machine", RevisionID: "revision", Type: "STANDARD", Status: "ACTIVE", Created: now}); err != nil {
						return err
					}
					if err := tx.PutActivity(stepfunctions.ActivityRecord{Key: stepfunctions.ActivityKey{Scope: s, Name: "activity"}, ID: "activity", Created: now}); err != nil {
						return err
					}
					if err := tx.PutExecution(execution(s, "running", "STANDARD", "RUNNING")); err != nil {
						return err
					}
				}
				if err := tx.PutMachine(machine); err != nil {
					return err
				}
				child := execution(scope, "child", "STANDARD", "RUNNING")
				child.MapRunARN = "map-run"
				for _, row := range []stepfunctions.ExecutionRecord{
					child,
					execution(scope, "pending", "STANDARD", "PENDING"),
					execution(scope, "failed", "STANDARD", "FAILED"),
					execution(scope, "express", "EXPRESS", "RUNNING"),
				} {
					if err := tx.PutExecution(row); err != nil {
						return err
					}
				}
				return check(tx, scope, [3]int64{2, 1, 2})
			}); err != nil {
				t.Fatal(err)
			}
			abort := errors.New("rollback resource transitions")
			for _, rollback := range []bool{true, false} {
				err := repo.Update(t.Context(), func(tx stepfunctions.Transaction) error {
					if err := tx.DeleteMachine(machine.Key); err != nil {
						return err
					}
					if err := tx.DeleteActivity(stepfunctions.ActivityKey{Scope: scope, Name: "activity"}); err != nil {
						return err
					}
					if err := tx.PutExecution(execution(scope, "running", "STANDARD", "SUCCEEDED")); err != nil {
						return err
					}
					if err := check(tx, scope, [3]int64{1, 0, 1}); err != nil {
						return err
					}
					if err := tx.PutExecution(execution(scope, "pending", "STANDARD", "RUNNING")); err != nil {
						return err
					}
					if err := check(tx, scope, [3]int64{1, 0, 2}); err != nil {
						return err
					}
					if err := tx.DeleteExecution(stepfunctions.ExecutionKey{Scope: scope, ARN: "child"}); err != nil {
						return err
					}
					if err := check(tx, scope, [3]int64{1, 0, 1}); err != nil {
						return err
					}
					if rollback {
						return abort
					}
					return nil
				})
				if rollback && !errors.Is(err, abort) || !rollback && err != nil {
					t.Fatalf("rollback=%v: %v", rollback, err)
				}
				if err := repo.View(t.Context(), func(r stepfunctions.Reader) error {
					want := [3]int64{1, 0, 1}
					if rollback {
						want = [3]int64{2, 1, 2}
					}
					if err := check(r, scope, want); err != nil {
						return err
					}
					for _, s := range scopes[1:] {
						if err := check(r, s, [3]int64{1, 1, 1}); err != nil {
							return err
						}
					}
					return nil
				}); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}
