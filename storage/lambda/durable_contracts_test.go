package lambda_test

import (
	"errors"
	"math"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	api "stackd/internal/awsapi/lambda"
	"stackd/storage/lambda"
	"stackd/storage/sqlite"
	sqllambda "stackd/storage/sqlite/lambda"
)

func durableExecutionFixture() lambda.DurableExecutionRecord {
	at := time.Date(2026, 9, 28, 12, 0, 0, 123456789, time.UTC)
	operation := lambda.DurableOperationRecord{
		ID: "child", ParentID: "parent", Name: "charge", Type: "STEP", SubType: "retry", Status: "PENDING",
		StartedAt: at.Add(time.Second), DueAt: at.Add(7 * time.Second), Payload: new(""),
		Error:   &api.ErrorObject{ErrorData: new(api.ErrorData("{}")), ErrorMessage: new(api.ErrorMessage("retry")), ErrorType: new(api.ErrorType("Unavailable")), StackTrace: api.StackTraceEntries{"handler:23", "step:11"}},
		Attempt: 3, ReplayChildren: true, CallbackID: "callback-token", CallbackTimeoutAt: at.Add(time.Hour), HeartbeatAt: at.Add(time.Minute), HeartbeatSeconds: 60, TimeoutSeconds: 3600,
		TargetFunction: "arn:aws:lambda:us-east-1:111111111111:function:target:2", TargetTenant: "tenant", Generation: math.MaxUint64 - 1,
	}
	before := operation
	before.Status, before.Attempt, before.Payload, before.Error = "STARTED", 1, nil, &api.ErrorObject{}
	before.DueAt, before.Generation = time.Time{}, 2
	return lambda.DurableExecutionRecord{
		ARN: "arn:aws:lambda:us-east-1:111111111111:function:function:1/durable-execution/run/id", Name: "run", ID: "id",
		Function: lambda.FunctionVersionKey{FunctionKey: deployment().Key, Version: 1}, Status: "RUNNING",
		Input: new("{\"order\":1}"), Result: nil, Error: &api.ErrorObject{ErrorMessage: new(api.ErrorMessage("")), StackTrace: api.StackTraceEntries{}},
		StartedAt: at, Deadline: at.Add(2 * time.Hour), ExpiresAt: at.Add(14 * 24 * time.Hour), ExecutionTimeout: 7200, RetentionDays: 14,
		Token: "current-token", Generation: math.MaxUint64 - 2, Claimed: true, NextRunAt: at.Add(7 * time.Second), InvocationType: "Event", TraceID: "trace", ClientContext: "context",
		Operations:  []lambda.DurableOperationRecord{operation},
		History:     []lambda.DurableEventRecord{{ID: 7, At: at.Add(time.Second), Type: "StepStarted", Operation: before}, {ID: 11, At: at.Add(2 * time.Second), Type: "StepFailed", Operation: operation}},
		Checkpoints: []lambda.DurableCheckpointRecord{{ClientToken: "client-token", PreviousToken: "previous-token", NextToken: "current-token", Request: []byte(`{"Updates":[{"Id":"child","Action":"START"}]}`), ExpiresAt: at.Add(15 * time.Minute), Operations: []lambda.DurableOperationRecord{before}}},
	}
}

func assertDurableExecution(t *testing.T, repo lambda.Repository, want lambda.DurableExecutionRecord) {
	t.Helper()
	if err := repo.View(t.Context(), func(r lambda.Reader) error {
		got, err := r.DurableExecution(want.ARN)
		if err != nil {
			return err
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("durable state differs:\ngot  %#v\nwant %#v", got, want)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestDurableSnapshotsDetachedAndRollbackAtomic(t *testing.T) {
	forRepositories(t, func(t *testing.T, repo lambda.Repository) {
		want, input := durableExecutionFixture(), durableExecutionFixture()
		if err := repo.Update(t.Context(), func(tx lambda.Transaction) error {
			if err := tx.PutDurableExecution(input); err != nil {
				return err
			}
			*input.Input = "caller mutation"
			*input.Error.ErrorMessage = "caller mutation"
			*input.Operations[0].Payload = "caller mutation"
			input.Operations[0].Error.StackTrace[0] = "caller mutation"
			input.Checkpoints[0].Request[0] = '!'
			input.Checkpoints[0].Operations[0].Error.ErrorType = new(api.ErrorType("caller mutation"))
			input.History[0].Operation.Name = "caller mutation"
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		assertDurableExecution(t, repo, want)
		if err := repo.View(t.Context(), func(r lambda.Reader) error {
			rows, err := r.DurableExecutions()
			if err != nil {
				return err
			}
			*rows[0].Input = "reader mutation"
			rows[0].Operations[0].Error.StackTrace[0] = "reader mutation"
			rows[0].Checkpoints[0].Request[0] = '!'
			rows[0].History[1].Operation.Error.ErrorData = nil
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		assertDurableExecution(t, repo, want)
		abort := errors.New("abort checkpoint")
		if err := repo.Update(t.Context(), func(tx lambda.Transaction) error {
			v, err := tx.DurableExecution(want.ARN)
			if err != nil {
				return err
			}
			v.Token, v.Claimed, v.NextRunAt = "new-token", false, v.NextRunAt.Add(time.Minute)
			v.Operations, v.History, v.Checkpoints, v.Error = nil, nil, nil, nil
			return repo.Update(tx.Context(), func(joined lambda.Transaction) error {
				if err := joined.PutDurableExecution(v); err != nil {
					return err
				}
				return abort
			})
		}); !errors.Is(err, abort) {
			t.Fatalf("borrowed checkpoint rollback: %v", err)
		}
		assertDurableExecution(t, repo, want)
		replacement := want
		replacement.Token, replacement.Claimed, replacement.NextRunAt = "terminal-token", false, time.Time{}
		replacement.Result, replacement.Input, replacement.Error = new(""), nil, nil
		replacement.Status, replacement.EndedAt = "SUCCEEDED", want.StartedAt.Add(time.Minute)
		replacement.Operations, replacement.History, replacement.Checkpoints = nil, nil, nil
		if err := repo.Update(t.Context(), func(tx lambda.Transaction) error { return tx.PutDurableExecution(replacement) }); err != nil {
			t.Fatal(err)
		}
		assertDurableExecution(t, repo, replacement)
	})
}

func TestDurableIdentityIsolationAndDeletion(t *testing.T) {
	forRepositories(t, func(t *testing.T, repo lambda.Repository) {
		want := durableExecutionFixture()
		other := durableExecutionFixture()
		other.ARN, other.Function.Account = "arn:aws:lambda:us-east-1:222222222222:function:function:1/durable-execution/run/id", "222222222222"
		if err := repo.Update(t.Context(), func(tx lambda.Transaction) error {
			if err := tx.PutDurableExecution(other); err != nil {
				return err
			}
			return tx.PutDurableExecution(want)
		}); err != nil {
			t.Fatal(err)
		}
		for _, mutate := range []func(*lambda.DurableExecutionRecord){
			func(v *lambda.DurableExecutionRecord) { v.Function.Account = "333333333333" },
			func(v *lambda.DurableExecutionRecord) { v.Function.Region = "us-west-2" },
			func(v *lambda.DurableExecutionRecord) { v.Function.Version = 2 },
			func(v *lambda.DurableExecutionRecord) { v.ID = "replacement-id" },
			func(v *lambda.DurableExecutionRecord) { v.Name = "replacement-name" },
			func(v *lambda.DurableExecutionRecord) { v.StartedAt = v.StartedAt.Add(time.Second) },
		} {
			v := want
			mutate(&v)
			if err := repo.Update(t.Context(), func(tx lambda.Transaction) error { return tx.PutDurableExecution(v) }); err == nil {
				t.Fatal("durable execution identity was overwritten")
			}
		}
		assertDurableExecution(t, repo, want)
		assertDurableExecution(t, repo, other)
		if err := repo.View(t.Context(), func(r lambda.Reader) error {
			rows, err := r.DurableExecutions()
			if err != nil {
				return err
			}
			if len(rows) != 2 || rows[0].ARN != want.ARN || rows[1].ARN != other.ARN {
				t.Fatalf("unstable recovery scan: %+v", rows)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		abort := errors.New("abort retention deletion")
		if err := repo.Update(t.Context(), func(tx lambda.Transaction) error {
			if err := tx.DeleteDurableExecution(want.ARN); err != nil {
				return err
			}
			return abort
		}); !errors.Is(err, abort) {
			t.Fatalf("delete rollback: %v", err)
		}
		assertDurableExecution(t, repo, want)
		if err := repo.Update(t.Context(), func(tx lambda.Transaction) error { return tx.DeleteDurableExecution(want.ARN) }); err != nil {
			t.Fatal(err)
		}
		if err := repo.View(t.Context(), func(r lambda.Reader) error {
			_, err := r.DurableExecution(want.ARN)
			if !errors.Is(err, lambda.ErrNotFound) {
				t.Fatalf("deleted execution: %v", err)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		assertDurableExecution(t, repo, other)
		// Reusing the key must not resurrect any removed payload, error or snapshot.
		want.Name, want.ID = "new-run", "new-id"
		want.Operations, want.History, want.Checkpoints, want.Error = nil, nil, nil, nil
		if err := repo.Update(t.Context(), func(tx lambda.Transaction) error { return tx.PutDurableExecution(want) }); err != nil {
			t.Fatal(err)
		}
		assertDurableExecution(t, repo, want)
	})
}

func TestDurableConfigurationSnapshotsAndRestart(t *testing.T) {
	forRepositories(t, func(t *testing.T, repo lambda.Repository) {
		latest := deployment()
		latest.Durable = &api.DurableConfig{ExecutionTimeout: new(api.ExecutionTimeout(7200)), RetentionPeriodInDays: new(api.RetentionPeriodInDays(14)), KMSKeyArn: new(api.KMSKeyArn(""))}
		published, pending := latest, deployment()
		published.Version = 1
		pending.Durable = &api.DurableConfig{ExecutionTimeout: new(api.ExecutionTimeout(900)), RetentionPeriodInDays: new(api.RetentionPeriodInDays(7))}
		if err := repo.Update(t.Context(), func(tx lambda.Transaction) error {
			if err := tx.PutFunction(latest); err != nil {
				return err
			}
			if err := tx.PutPendingFunction(pending); err != nil {
				return err
			}
			return tx.PutFunctionVersion(published)
		}); err != nil {
			t.Fatal(err)
		}
		*latest.Durable.ExecutionTimeout = 100
		if err := repo.View(t.Context(), func(r lambda.Reader) error {
			current, err := r.Function(latest.Key)
			if err != nil {
				return err
			}
			staged, err := r.PendingFunction(latest.Key)
			if err != nil {
				return err
			}
			version, err := r.FunctionVersion(lambda.FunctionVersionKey{FunctionKey: latest.Key, Version: 1})
			if err != nil {
				return err
			}
			if *current.Durable.ExecutionTimeout != 7200 || *staged.Durable.ExecutionTimeout != 900 || *version.Durable.ExecutionTimeout != 7200 || current.Durable.KMSKeyArn == nil || staged.Durable.KMSKeyArn != nil {
				t.Fatal("durable config snapshots aliased or lost nullable fields")
			}
			*version.Durable.ExecutionTimeout = 1
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		if err := repo.Update(t.Context(), func(tx lambda.Transaction) error {
			version, err := tx.FunctionVersion(lambda.FunctionVersionKey{FunctionKey: latest.Key, Version: 1})
			if err != nil {
				return err
			}
			if *version.Durable.ExecutionTimeout != 7200 {
				t.Fatal("reader mutation changed published durable configuration")
			}
			if err := tx.DeleteFunction(latest.Key); err != nil {
				return err
			}
			return tx.PutFunction(deployment())
		}); err != nil {
			t.Fatal(err)
		}
		if err := repo.View(t.Context(), func(r lambda.Reader) error {
			v, err := r.Function(latest.Key)
			if err != nil {
				return err
			}
			if v.Durable != nil {
				t.Fatal("recreated function inherited deleted durable configuration")
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("sqlite-restart", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "durable.sqlite")
		db, err := sqlite.Open(t.Context(), path)
		if err != nil {
			t.Fatal(err)
		}
		want := durableExecutionFixture()
		latest := deployment()
		latest.Durable = &api.DurableConfig{ExecutionTimeout: new(api.ExecutionTimeout(7200)), RetentionPeriodInDays: new(api.RetentionPeriodInDays(14))}
		if err := sqllambda.New(db).Update(t.Context(), func(tx lambda.Transaction) error {
			if err := tx.PutFunction(latest); err != nil {
				return err
			}
			return tx.PutDurableExecution(want)
		}); err != nil {
			db.Close()
			t.Fatal(err)
		}
		if err := db.Close(); err != nil {
			t.Fatal(err)
		}
		db, err = sqlite.Open(t.Context(), path)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if err := db.Close(); err != nil {
				t.Error(err)
			}
		})
		repo := sqllambda.New(db)
		assertDurableExecution(t, repo, want)
		if err := repo.View(t.Context(), func(r lambda.Reader) error {
			v, err := r.Function(latest.Key)
			if err != nil {
				return err
			}
			if !reflect.DeepEqual(v.Durable, latest.Durable) {
				t.Fatalf("durable configuration lost on reopen: %+v", v.Durable)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		if err := repo.Update(t.Context(), func(tx lambda.Transaction) error { return tx.DeleteFunction(latest.Key) }); err != nil {
			t.Fatal(err)
		}
		assertDurableExecution(t, repo, want)
	})
}
