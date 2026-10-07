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
)

type missingSnapshotSource struct{ controlledRuntime }

func (missingSnapshotSource) Snapshot(context.Context, engine.Specification, string) error {
	return errors.New("retained native source does not exist")
}

func TestDetachedClusterSnapshotFailureNeverProvisionsAnEmptyDatabase(t *testing.T) {
	now := time.Date(2031, 1, 1, 0, 0, 0, 0, time.UTC)
	ensures := 0
	s := New(Config{Clock: clock.NewManual(now), Cipher: testCipher{}, Runtime: missingSnapshotSource{controlledRuntime{ensure: func(context.Context, engine.Specification) (engine.Endpoint, error) {
		ensures++
		return engine.Endpoint{Address: "127.0.0.1", Port: 15432}, nil
	}}}})
	t.Cleanup(func() { _ = s.Close() })
	v := retainedDatabase(now)
	v.Key.Kind, v.Engine, v.Class = "cluster", "aurora-postgresql", ""
	v.Status, v.Operation, v.Due = "creating", "", time.Time{}
	seedDatabase(t, s, v)
	ctx := awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: v.Key.Partition, AccountID: v.Key.AccountID, Region: v.Key.Region, PrincipalARN: "arn:aws:iam::111111111111:root", PrincipalID: v.Key.AccountID})
	if err := s.repository.Attempt(ctx, func(tx Transaction) error {
		_, err := s.captureSnapshot(ctx, tx, "cluster", v.Key.Name, "final-backup", nil)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	job, found, err := (snapshotJobs{s}).Next(ctx)
	if err != nil || !found {
		t.Fatalf("snapshot work missing: %v, %v", found, err)
	}
	if err := (snapshotJobs{s}).Run(ctx, job); err != nil {
		t.Fatal(err)
	}
	if ensures != 0 {
		t.Fatal("failed detached backup provisioned an empty replacement engine")
	}
	if got := readDatabase(t, s, v.Key); got.Status != "creating" || got.Operation != "" || !got.Due.IsZero() || got.Endpoint.Address != "" {
		t.Fatalf("failed backup fabricated writer readiness: %#v", got)
	}
	if err := s.repository.View(ctx, func(reader Reader) error {
		got, err := reader.Snapshot(Key{Scope: v.Key.Scope, Kind: "cluster-snapshot", Name: "final-backup"})
		if err != nil {
			return err
		}
		if got.Status != "failed" {
			t.Fatalf("failed native copy was reported as completed: %#v", got)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestCommittedPasswordIntentOnlyRecoversExactCommand(t *testing.T) {
	for _, password := range []string{"test-password", "different-password"} {
		t.Run(password, func(t *testing.T) {
			now := time.Date(2031, 1, 1, 0, 0, 0, 0, time.UTC)
			s := New(Config{Clock: clock.NewManual(now), Cipher: testCipher{}})
			t.Cleanup(func() { _ = s.Close() })
			v := retainedDatabase(now)
			v.Status, v.Operation, v.Version = "modifying", "password", 13
			v.PendingCiphertext = []byte{0x81, 0x42}
			seedDatabase(t, s, v)
			ctx := awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: v.Key.Partition, AccountID: v.Key.AccountID, Region: v.Key.Region, PrincipalARN: "arn:aws:iam::111111111111:root", PrincipalID: v.Key.AccountID})
			err := s.repository.Attempt(ctx, func(tx Transaction) error {
				_, err := s.modifyDatabase(ctx, tx, "ModifyDBInstance", "db", v.Key.Name, new(api.SensitiveString(password)), nil, nil, nil, new(api.Boolean(true)))
				return err
			})
			if password == "test-password" && err != nil {
				t.Fatalf("exact committed intent could not recover: %v", err)
			}
			if password != "test-password" && err == nil {
				t.Fatal("unrelated password was adopted as already applied")
			}
			if got := readDatabase(t, s, v.Key); got.Version != v.Version || got.Operation != "password" {
				t.Fatalf("retry overwrote native intent: %#v", got)
			}
		})
	}
}
