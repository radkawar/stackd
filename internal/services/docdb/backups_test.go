package docdb

import (
	"context"
	"errors"
	"testing"
	"time"

	"stackd/clock"
	engine "stackd/engine/docdb"
	api "stackd/internal/awsapi/docdb"
	"stackd/internal/awsctx"
)

type backupCipher struct{}

func (backupCipher) Seal(_ context.Context, _, user, password string) ([]byte, error) {
	return []byte(user + "\x00" + password), nil
}
func (backupCipher) Open(_ context.Context, _ string, _ []byte) (string, string, error) {
	return "owner", "test-password", nil
}

type backupRuntime struct {
	captures, deletions []string
	failure             error
}

func (*backupRuntime) Ensure(context.Context, engine.Specification) (engine.Endpoint, error) {
	return engine.Endpoint{Address: "127.0.0.1", Port: 27017}, nil
}
func (*backupRuntime) Stop(context.Context, string) error   { return nil }
func (*backupRuntime) Delete(context.Context, string) error { return nil }
func (r *backupRuntime) Snapshot(_ context.Context, spec engine.Specification, id string) error {
	r.captures = append(r.captures, spec.ID+"/"+id)
	return r.failure
}
func (*backupRuntime) Restore(context.Context, engine.Specification, string) (engine.Endpoint, error) {
	return engine.Endpoint{}, nil
}
func (r *backupRuntime) DeleteSnapshot(_ context.Context, id string) error {
	r.deletions = append(r.deletions, id)
	return nil
}
func (*backupRuntime) SetPassword(context.Context, engine.Specification, string) error { return nil }
func (*backupRuntime) Close() error                                                    { return nil }

func backupFixture(t *testing.T) (*Service, *clock.Manual, *backupRuntime, Cluster) {
	t.Helper()
	now := time.Date(2031, 1, 1, 8, 59, 0, 0, time.UTC)
	timeline := clock.NewManual(now)
	runtime := &backupRuntime{}
	s := New(Config{Clock: timeline, Runtime: runtime, Cipher: backupCipher{}})
	t.Cleanup(func() { _ = s.Close() })
	v := Cluster{Key: Key{Scope: Scope{Partition: "aws", AccountID: "111111111111", Region: "us-east-1"}, Kind: "cluster", Name: "source"}, RuntimeID: "11111111111111111111111111111111", Username: "owner", EngineVersion: "5.0", Status: "available", Ciphertext: []byte("sealed"), Version: 1, Endpoint: engine.Endpoint{Address: "127.0.0.1", Port: 27017}, BackupRetention: 1, BackupWindow: defaultBackupWindow, NextBackup: nextBackup(now, defaultBackupWindow)}
	if err := s.repository.Update(t.Context(), func(tx Transaction) error {
		if err := tx.PutCluster(v); err != nil {
			return err
		}
		return tx.PutInstance(Instance{Key: Key{Scope: v.Key.Scope, Kind: "db", Name: "writer"}, Cluster: v.Key.Name, Status: "available"})
	}); err != nil {
		t.Fatal(err)
	}
	return s, timeline, runtime, v
}

func TestBackupWindowValidationAndMidnight(t *testing.T) {
	for _, tc := range []struct {
		days   int32
		window string
		valid  bool
	}{
		{1, "09:00-09:30", true}, {35, "23:45-00:30", true},
		{0, "09:00-09:30", false}, {36, "09:00-09:30", false},
		{1, "09:00-09:29", false}, {1, "9:00-09:30", false}, {1, "24:00-00:30", false},
	} {
		if err := validateBackups(tc.days, tc.window); (err == nil) != tc.valid {
			t.Fatalf("%+v: %v", tc, err)
		}
	}
	now := time.Date(2031, 1, 1, 23, 45, 0, 0, time.UTC)
	if got := nextBackup(now, "23:45-00:30"); !got.Equal(now.Add(24 * time.Hour)) {
		t.Fatalf("next daily window: %v", got)
	}
}

func TestBackupIntentNativeRetryAndScopedExpiry(t *testing.T) {
	s, timeline, native, source := backupFixture(t)
	timeline.Advance(time.Minute)
	owner := backupJobs{s}
	job, found, err := owner.Next(t.Context())
	if err != nil || !found {
		t.Fatalf("backup selection: %v %v", found, err)
	}
	if err := owner.Run(t.Context(), job); err != nil {
		t.Fatal(err)
	}
	if len(native.captures) != 0 {
		t.Fatal("external snapshot ran inside intent admission")
	}
	if err := owner.Run(t.Context(), job); err != nil {
		t.Fatal(err)
	}
	var snap Snapshot
	if err := s.repository.View(t.Context(), func(r Reader) error {
		all, err := r.Snapshots()
		if err != nil {
			return err
		}
		if len(all) != 1 {
			t.Fatalf("replayed schedule duplicated snapshots: %d", len(all))
		}
		snap = all[0]
		v, err := r.Cluster(source.Key)
		if err != nil {
			return err
		}
		if !snap.Automated || snap.SourceRuntimeID != source.RuntimeID || v.Status != "backing-up" || v.Endpoint.Address != "" || !v.NextBackup.Equal(job.Due.Add(24*time.Hour)) {
			t.Fatalf("invalid retained snapshot ownership: %#v %#v", snap, v)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	worker := snapshotJobs{s}
	native.failure = errors.New("native snapshot not published")
	work, _, err := worker.Next(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if err := worker.Run(t.Context(), work); err != nil {
		t.Fatal(err)
	}
	timeline.Advance(healthInterval)
	native.failure = nil
	work, _, err = worker.Next(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if err := worker.Run(t.Context(), work); err != nil {
		t.Fatal(err)
	}
	if len(native.captures) != 2 || native.captures[0] != native.captures[1] {
		t.Fatalf("retry changed native ownership: %v", native.captures)
	}
	restored := Key{Scope: source.Key.Scope, Kind: "cluster", Name: "restored"}
	if err := s.repository.Update(t.Context(), func(tx Transaction) error {
		return tx.PutCluster(Cluster{Key: restored, RestoreSnapshot: snap.RuntimeID})
	}); err != nil {
		t.Fatal(err)
	}
	timeline.Advance(24 * time.Hour)
	work, _, err = worker.Next(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if err := worker.Run(t.Context(), work); err != nil {
		t.Fatal(err)
	}
	if len(native.deletions) != 0 {
		t.Fatal("expiry deleted a pinned restore source")
	}
	if err := s.repository.Update(t.Context(), func(tx Transaction) error { return tx.DeleteCluster(restored) }); err != nil {
		t.Fatal(err)
	}
	foreign := restored
	foreign.AccountID = "222222222222"
	if err := s.repository.Update(t.Context(), func(tx Transaction) error {
		return tx.PutCluster(Cluster{Key: foreign, RestoreSnapshot: snap.RuntimeID})
	}); err != nil {
		t.Fatal(err)
	}
	timeline.Advance(healthInterval)
	work, _, err = worker.Next(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if err := worker.Run(t.Context(), work); err != nil {
		t.Fatal(err)
	}
	if len(native.deletions) != 0 {
		t.Fatal("expiry skipped retirement intent")
	}
	work, _, err = worker.Next(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if err := worker.Run(t.Context(), work); err != nil {
		t.Fatal(err)
	}
	if len(native.deletions) != 1 || native.deletions[0] != snap.RuntimeID {
		t.Fatalf("wrong native snapshot retired: %v", native.deletions)
	}
	if err := s.repository.View(t.Context(), func(r Reader) error {
		_, err := r.Snapshot(snap.Key)
		if !errors.Is(err, ErrNotFound) {
			t.Fatalf("snapshot remains after native deletion: %v", err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestEmptyClusterIsNotNativeReady(t *testing.T) {
	s, _, _, v := backupFixture(t)
	ctx := awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: v.Key.Partition, AccountID: v.Key.AccountID, Region: v.Key.Region, PrincipalARN: "arn:aws:iam::111111111111:root"})
	if err := s.repository.Update(ctx, func(tx Transaction) error {
		if err := tx.DeleteInstance(Key{Scope: v.Key.Scope, Kind: "db", Name: "writer"}); err != nil {
			return err
		}
		v.Endpoint = engine.Endpoint{}
		return tx.PutCluster(v)
	}); err != nil {
		t.Fatal(err)
	}
	got, err := s.ResolveCluster(ctx, v.Key.ARN())
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != "available" || got.Ready || got.Endpoint.Address != "" {
		t.Fatalf("empty control plane advertised native readiness: %#v", got)
	}
	var created *api.CreateDBInstanceOutput
	if err := s.repository.Update(ctx, func(tx Transaction) error {
		var err error
		created, err = s.createInstance(ctx, tx, &api.CreateDBInstanceInput{Engine: new(api.String("docdb")), DBClusterIdentifier: new(api.String(v.Key.Name)), DBInstanceIdentifier: new(api.String("writer")), DBInstanceClass: new(api.String("db.r5.large")), PromotionTier: new(api.IntegerOptional(0))})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if value(created.DBInstance.DBInstanceStatus) != "creating" {
		t.Fatalf("native create falsely ready: %#v", created)
	}
}
