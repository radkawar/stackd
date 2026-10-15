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

func TestEmptyClusterControlPrecedesNativeWriter(t *testing.T) {
	now := time.Date(2031, 1, 1, 0, 0, 0, 0, time.UTC)
	s := New(Config{Clock: clock.NewManual(now), Runtime: controlledRuntime{}, Cipher: testCipher{}})
	t.Cleanup(func() { _ = s.Close() })
	ctx := awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: "aws", AccountID: "111111111111", Region: "us-east-1", PrincipalARN: "arn:aws:iam::111111111111:root"})
	name, eng, version, user := api.String("owned-cluster"), api.String("aurora-postgresql"), api.String("17.11"), api.String("owner")
	password := api.SensitiveString("test-password")
	var cluster Key
	if err := s.repository.Update(ctx, func(tx Transaction) error {
		out, err := s.createCluster(ctx, tx, &api.CreateDBClusterMessage{DBClusterIdentifier: &name, Engine: &eng, EngineVersion: &version, MasterUsername: &user, MasterUserPassword: &password})
		if err != nil {
			return err
		}
		if value(out.DBCluster.Status) != "available" || out.DBCluster.Endpoint != nil {
			t.Fatal("empty cluster must expose only its available control resource")
		}
		cluster = Key{Scope: scopeFor(ctx), Kind: "cluster", Name: string(name)}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	control := readDatabase(t, s, cluster)
	if control.Operation != "" || !control.Due.IsZero() || control.Endpoint.Address != "" {
		t.Fatal("empty cluster scheduled or exposed a native engine")
	}
	resolved, err := s.ResolveDataCluster(ctx, cluster.ARN())
	if err != nil || resolved.Status == "available" || resolved.Endpoint.Address != "" {
		t.Fatalf("empty cluster admitted SQL: %+v %v", resolved, err)
	}
	writer, class := api.String("owned-writer"), api.String("db.t3.micro")
	if err := s.repository.Update(ctx, func(tx Transaction) error {
		_, err := s.createWriter(ctx, tx, Key{Scope: cluster.Scope, Kind: "db", Name: string(writer)}, &api.CreateDBInstanceMessage{
			DBInstanceIdentifier: &writer, DBClusterIdentifier: &name, Engine: &eng, EngineVersion: &version, DBInstanceClass: &class,
		})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	pending := readDatabase(t, s, cluster)
	if pending.Status != "creating" || pending.Operation != "create" || pending.Due != now || pending.Endpoint.Address != "" {
		t.Fatal("writer admission did not retain a fenced native creation intent")
	}
	if err := (databaseJobs{s}).Run(ctx, selectDatabase(t, s)); err != nil {
		t.Fatal(err)
	}
	if current := readDatabase(t, s, cluster); current.Status != "available" || current.Endpoint.Address == "" {
		t.Fatal("native completion did not publish its authenticated endpoint")
	}
}

func TestStartupDoesNotReconcileMemberlessCluster(t *testing.T) {
	now := time.Date(2031, 1, 1, 0, 0, 0, 0, time.UTC)
	s := New(Config{Clock: clock.NewManual(now), Runtime: controlledRuntime{}, Cipher: testCipher{}})
	t.Cleanup(func() { _ = s.Close() })
	cluster := retainedDatabase(now)
	cluster.Key.Kind, cluster.Engine = "cluster", "aurora-postgresql"
	cluster.Status, cluster.Operation, cluster.Due = "creating", "create", time.Time{}
	seedDatabase(t, s, cluster)
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	current := readDatabase(t, s, cluster.Key)
	if current.Status != "available" || !current.Due.IsZero() || current.Endpoint.Address != "" {
		t.Fatal("startup fabricated an empty cluster SQL endpoint or scheduled native work")
	}
	if _, found, err := (databaseJobs{s}).Next(t.Context()); err != nil || found {
		t.Fatalf("memberless cluster retained native work: found=%v error=%v", found, err)
	}
}

func TestRestoredClusterRetainsNativeSnapshotUntilWriter(t *testing.T) {
	now := time.Date(2031, 1, 1, 0, 0, 0, 0, time.UTC)
	s := New(Config{Clock: clock.NewManual(now), Runtime: controlledRuntime{}, Cipher: testCipher{}})
	t.Cleanup(func() { _ = s.Close() })
	ctx := awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: "aws", AccountID: "111111111111", Region: "us-east-1", PrincipalARN: "arn:aws:iam::111111111111:root"})
	key := Key{Scope: scopeFor(ctx), Kind: "cluster-snapshot", Name: "captured-cluster"}
	if err := s.repository.Update(ctx, func(tx Transaction) error {
		if err := tx.PutSnapshot(Snapshot{Key: key, Engine: "aurora-postgresql", EngineVersion: "17.11", DatabaseName: "proof", RuntimeID: "immutable-capture", Status: "available", Ciphertext: []byte{0x81, 0x42}, Parameters: map[string]string{}, Tags: map[string]string{}}); err != nil {
			return err
		}
		current, err := s.restoreDatabase(ctx, tx, "cluster", "restored-control", key.Name, "aurora-postgresql", "17.11", "", "", "", nil, nil)
		if err != nil {
			return err
		}
		if current.Status != "available" || !current.Due.IsZero() || current.Endpoint.Address != "" || current.Operation != "restore" || current.RestoreSnapshot != "immutable-capture" {
			t.Fatal("restored control lost native capture intent or fabricated SQL readiness")
		}
		return tx.PutDatabase(current)
	}); err != nil {
		t.Fatal(err)
	}
	current, err := s.ResolveDataCluster(ctx, Key{Scope: key.Scope, Kind: "cluster", Name: "restored-control"}.ARN())
	if err != nil || current.Status == "available" || current.Endpoint.Address != "" {
		t.Fatalf("restored memberless control admitted SQL: %+v %v", current, err)
	}
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
