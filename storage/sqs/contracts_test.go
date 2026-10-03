package sqs_test

import (
	"path/filepath"
	"testing"

	"stackd/storage/sqlite"
	sqlsqs "stackd/storage/sqlite/sqs"

	"stackd/storage/sqs"
)

func TestRedriveCallerCopiesAndTransactionLifetime(t *testing.T) {
	for _, makeBackend := range []struct {
		name string
		new  func(*testing.T) sqs.Repository
	}{
		{"memory", func(t *testing.T) sqs.Repository { return sqs.NewMemory(nil) }},
		{"sqlite", func(t *testing.T) sqs.Repository {
			db, err := sqlite.Open(t.Context(), filepath.Join(t.TempDir(), "sqs.sqlite"))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := db.Close(); err != nil {
					t.Error(err)
				}
			})
			return sqlsqs.New(db)
		}},
	} {
		t.Run(makeBackend.name, func(t *testing.T) {
			repo := makeBackend.new(t)
			task := sqs.MoveTaskRecord{Handle: "task", Caller: sqs.CallerMetadata{
				SessionPolicies: []string{"policy"}, SessionPolicyARNs: []string{"arn"}, SessionTags: map[string]string{"key": "tag"}, TransitiveTagKeys: []string{"key"},
			}}
			var escaped sqs.Transaction
			if err := repo.Update(t.Context(), func(tx sqs.Transaction) error { escaped = tx; return tx.PutMoveTask(task) }); err != nil {
				t.Fatal(err)
			}
			task.Caller.SessionPolicies[0] = "changed"
			task.Caller.SessionPolicyARNs[0] = "changed"
			task.Caller.SessionTags["key"] = "changed"
			task.Caller.TransitiveTagKeys[0] = "changed"
			if err := escaped.PutMoveTask(task); err == nil {
				t.Fatal("escaped transaction can write")
			}
			if _, err := escaped.MoveTasks(); err == nil {
				t.Fatal("escaped transaction can read")
			}
			var reader sqs.Reader
			for range 2 {
				if err := repo.View(t.Context(), func(r sqs.Reader) error {
					reader = r
					tasks, err := r.MoveTasks()
					if err != nil {
						return err
					}
					caller := tasks[0].Caller
					if caller.SessionPolicies[0] != "policy" || caller.SessionPolicyARNs[0] != "arn" || caller.SessionTags["key"] != "tag" || caller.TransitiveTagKeys[0] != "key" {
						t.Fatal("stored caller aliases mutable values")
					}
					caller.SessionPolicies[0] = "changed"
					caller.SessionPolicyARNs[0] = "changed"
					caller.SessionTags["key"] = "changed"
					caller.TransitiveTagKeys[0] = "changed"
					return nil
				}); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := reader.MoveTasks(); err == nil {
				t.Fatal("escaped reader can read")
			}
		})
	}
}
