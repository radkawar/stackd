package rds

import (
	"context"
	"errors"
	"testing"
	"time"

	"stackd/clock"
	engine "stackd/engine/rds"
	api "stackd/internal/awsapi/rds"
	"stackd/internal/awsctx"
	"stackd/internal/scheduler"
)

type controlledRuntime struct {
	ensure func(context.Context, engine.Specification) (engine.Endpoint, error)
}

func (r controlledRuntime) Ensure(ctx context.Context, spec engine.Specification) (engine.Endpoint, error) {
	if r.ensure != nil {
		return r.ensure(ctx, spec)
	}
	return engine.Endpoint{Address: "127.0.0.1", Port: 15432}, nil
}

func (controlledRuntime) Stop(context.Context, string) error {
	return nil
}

func (controlledRuntime) Delete(context.Context, string) error {
	return nil
}

func (controlledRuntime) Snapshot(context.Context, engine.Specification, string) error {
	return nil
}

func (r controlledRuntime) Restore(ctx context.Context, spec engine.Specification, _ string) (engine.Endpoint, error) {
	return r.Ensure(ctx, spec)
}

func (controlledRuntime) DeleteSnapshot(context.Context, string) error {
	return nil
}

func (controlledRuntime) SetPassword(context.Context, engine.Specification, string) error {
	return nil
}

func (controlledRuntime) Statistics(context.Context, engine.Specification) (engine.Statistics, error) {
	return engine.Statistics{Connections: 2}, nil
}

func (controlledRuntime) Close() error {
	return nil
}

type testCipher struct{}

func (testCipher) Seal(context.Context, string, string, string) ([]byte, error) {
	return []byte{0x81, 0x42}, nil
}

func (testCipher) Open(context.Context, string, []byte) (string, string, error) {
	return "owner", "test-password", nil
}

func retainedDatabase(now time.Time) Database {
	return Database{Key: Key{Scope: Scope{"aws", "111111111111", "us-east-1"}, Kind: "db", Name: "owned"}, Engine: "postgres", EngineVersion: "17.11", Username: "owner", RuntimeID: "incarnation-a", Class: "db.t3.micro", Ciphertext: []byte{0x81, 0x42}, Status: "creating", Desired: "running", Operation: "create", Version: 1, Created: now, Due: now, Tags: map[string]string{}, Parameters: map[string]string{}}
}

func seedDatabase(t *testing.T, s *Service, v Database) {
	t.Helper()
	if e := s.repository.Update(t.Context(), func(tx Transaction) error {
		return tx.PutDatabase(v)
	}); e != nil {
		t.Fatal(e)
	}
}

func readDatabase(t *testing.T, s *Service, k Key) Database {
	t.Helper()
	var v Database
	if e := s.repository.View(t.Context(), func(r Reader) error {
		var e error
		v, e = r.Database(k)
		return e
	}); e != nil {
		t.Fatal(e)
	}
	return v
}

func selectDatabase(t *testing.T, s *Service) scheduler.Job {
	t.Helper()
	job, found, e := (databaseJobs{s}).Next(t.Context())
	if e != nil || !found {
		t.Fatalf("expected retained database job: found=%v err=%v", found, e)
	}
	return job
}

func TestNativeCompletionCannotResurrectDeletingDatabase(t *testing.T) {
	now := time.Date(2031, 1, 1, 0, 0, 0, 0, time.UTC)
	entered, release := make(chan struct{}), make(chan struct{})
	runtime := controlledRuntime{ensure: func(ctx context.Context, _ engine.Specification) (engine.Endpoint, error) {
		close(entered)
		select {
		case <-release:
			return engine.Endpoint{Address: "127.0.0.1", Port: 15432}, nil
		case <-ctx.Done():
			return engine.Endpoint{}, ctx.Err()
		}
	}}
	s := New(Config{Runtime: runtime, Cipher: testCipher{}, Clock: clock.NewManual(now)})
	t.Cleanup(func() {
		_ = s.Close()
	})
	v := retainedDatabase(now)
	seedDatabase(t, s, v)
	job := selectDatabase(t, s)
	done := make(chan error, 1)
	go func() {
		done <- (databaseJobs{s}).Run(t.Context(), job)
	}()
	<-entered
	ctx := awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: v.Key.Partition, AccountID: v.Key.AccountID, Region: v.Key.Region, PrincipalARN: "arn:aws:iam::111111111111:root"})
	e := s.repository.Update(ctx, func(tx Transaction) error {
		_, e := s.deleteDatabase(tx.Context(), tx, "db", v.Key.Name, new(api.Boolean(true)), nil, nil)
		return e
	})
	if e != nil {
		close(release)
		t.Fatal(e)
	}
	close(release)
	if e = <-done; e != nil {
		t.Fatal(e)
	}
	got := readDatabase(t, s, v.Key)
	if got.Status != "deleting" || got.Endpoint.Address != "" || got.Operation != "delete" {
		t.Fatalf("stale native completion overwrote deletion: status=%s operation=%s endpoint=%v", got.Status, got.Operation, got.Endpoint)
	}
	if e = (databaseJobs{s}).Run(t.Context(), selectDatabase(t, s)); e != nil {
		t.Fatal(e)
	}
	e = s.repository.View(t.Context(), func(r Reader) error {
		_, e := r.Database(v.Key)
		return e
	})
	if !errors.Is(e, ErrNotFound) {
		t.Fatalf("deleted database survived cleanup: %v", e)
	}
}

func TestPeriodicReadinessPreservesPendingReboot(t *testing.T) {
	now := time.Date(2031, 1, 1, 0, 0, 0, 0, time.UTC)
	s := New(Config{Runtime: controlledRuntime{}, Cipher: testCipher{}, Clock: clock.NewManual(now)})
	t.Cleanup(func() {
		_ = s.Close()
	})
	v := retainedDatabase(now)
	v.Status = "available"
	v.Operation = ""
	v.ParameterGroup = "configured"
	v.Parameters = map[string]string{"statement_timeout": "1000"}
	v.PendingParameters = true
	seedDatabase(t, s, v)
	if e := (databaseJobs{s}).Run(t.Context(), selectDatabase(t, s)); e != nil {
		t.Fatal(e)
	}
	got := readDatabase(t, s, v.Key)
	if !got.PendingParameters || got.Parameters["statement_timeout"] != "1000" || parameterStatus(got) != "pending-reboot" {
		t.Fatalf("health check applied or discarded pending parameter configuration: %#v", got)
	}
}

type rejectingMetrics struct {
	err error
}

func (m rejectingMetrics) PublishRDSMetric(context.Context, RDSMetric) error {
	return m.err
}

func TestMetricFailureDoesNotRollBackNativeReadiness(t *testing.T) {
	now := time.Date(2031, 1, 1, 0, 0, 0, 0, time.UTC)
	rejected := errors.New("metric owner unavailable")
	s := New(Config{Runtime: controlledRuntime{}, Cipher: testCipher{}, Clock: clock.NewManual(now), Metrics: rejectingMetrics{rejected}})
	t.Cleanup(func() {
		_ = s.Close()
	})
	v := retainedDatabase(now)
	seedDatabase(t, s, v)
	if e := (databaseJobs{s}).Run(t.Context(), selectDatabase(t, s)); !errors.Is(e, rejected) {
		t.Fatalf("metric owner failure was lost: %v", e)
	}
	got := readDatabase(t, s, v.Key)
	if got.Status != "available" || got.Endpoint.Address == "" || !got.Due.After(now) {
		t.Fatalf("metric failure rolled back native readiness: %#v", got)
	}
}

func TestNativeFailureRetainsUnavailableReconciliationIntent(t *testing.T) {
	now := time.Date(2031, 1, 1, 0, 0, 0, 0, time.UTC)
	s := New(Config{Runtime: controlledRuntime{ensure: func(context.Context, engine.Specification) (engine.Endpoint, error) {
		return engine.Endpoint{}, errors.New("native failed")
	}}, Cipher: testCipher{}, Clock: clock.NewManual(now)})
	t.Cleanup(func() {
		_ = s.Close()
	})
	v := retainedDatabase(now)
	seedDatabase(t, s, v)
	if e := (databaseJobs{s}).Run(t.Context(), selectDatabase(t, s)); e != nil {
		t.Fatal(e)
	}
	got := readDatabase(t, s, v.Key)
	if got.Status != "failed" || got.Endpoint.Address != "" || got.Operation != "create" || !got.Due.After(now) {
		t.Fatalf("failed native creation claimed readiness or lost intent: %#v", got)
	}
}
