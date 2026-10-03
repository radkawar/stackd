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

func TestImmediateParametersPreserveDeferredSettings(t *testing.T) {
	now := time.Date(2031, 1, 1, 0, 0, 0, 0, time.UTC)
	s := New(Config{Runtime: controlledRuntime{}, Cipher: testCipher{}, Clock: clock.NewManual(now)})
	t.Cleanup(func() { _ = s.Close() })
	v := retainedDatabase(now)
	v.Status, v.Operation, v.ParameterGroup = "available", "", "configured"
	v.Parameters = map[string]string{"max_connections": "100", "statement_timeout": "1000", "work_mem": "4MB"}
	v.PendingParameters = true
	seedDatabase(t, s, v)
	ctx := awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: v.Key.Partition, AccountID: v.Key.AccountID, Region: v.Key.Region, PrincipalARN: "arn:aws:iam::111111111111:root"})
	group := ParameterGroup{Key: Key{Scope: v.Key.Scope, Kind: "pg", Name: v.ParameterGroup}, Family: "postgres17", Parameters: map[string]string{"max_connections": "150", "statement_timeout": "1000", "work_mem": "8MB"}, ApplyMethods: map[string]string{}}
	if err := s.repository.Update(ctx, func(tx Transaction) error { return tx.PutParameterGroup(group) }); err != nil {
		t.Fatal(err)
	}
	if err := s.repository.Update(ctx, func(tx Transaction) error {
		_, err := s.changeParameters(ctx, tx, "pg", group.Key.Name, api.ParametersList{{ParameterName: new(api.String("statement_timeout")), ParameterValue: new(api.PotentiallySensitiveParameterValue("2000")), ApplyMethod: new(api.ApplyMethod("immediate"))}}, false, false)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	got := readDatabase(t, s, v.Key)
	if got.Parameters["statement_timeout"] != "2000" || got.Parameters["max_connections"] != "100" || got.Parameters["work_mem"] != "4MB" || !got.PendingParameters || parameterStatus(got) != "applying" {
		t.Fatalf("immediate intent lost deferred boundaries: %#v", got)
	}
	if err := (databaseJobs{s}).Run(ctx, selectDatabase(t, s)); err != nil {
		t.Fatal(err)
	}
	if got := readDatabase(t, s, v.Key); got.Status != "available" || parameterStatus(got) != "pending-reboot" {
		t.Fatalf("native completion discarded pending reboot: %#v", got)
	}
	if err := s.repository.Update(ctx, func(tx Transaction) error {
		_, err := s.changeParameters(ctx, tx, "pg", group.Key.Name, nil, true, true)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	got = readDatabase(t, s, v.Key)
	if _, exists := got.Parameters["statement_timeout"]; exists {
		t.Fatal("reset-all retained dynamic setting")
	}
	if _, exists := got.Parameters["work_mem"]; exists {
		t.Fatal("reset-all retained a previously deferred dynamic setting")
	}
	if got.Parameters["max_connections"] != "100" || !got.PendingParameters {
		t.Fatalf("reset-all prematurely reset static setting: %#v", got)
	}
}

func TestParameterBatchRejectionDoesNotMutateAttachedState(t *testing.T) {
	for _, rejected := range []api.Parameter{
		{ParameterName: new(api.String("max_connections")), ParameterValue: new(api.PotentiallySensitiveParameterValue("150")), ApplyMethod: new(api.ApplyMethod("immediate"))},
		{ParameterName: new(api.String("listen_addresses")), ParameterValue: new(api.PotentiallySensitiveParameterValue("*")), ApplyMethod: new(api.ApplyMethod("immediate"))},
		{ParameterName: new(api.String("statement_timeout")), ParameterValue: new(api.PotentiallySensitiveParameterValue("-1")), ApplyMethod: new(api.ApplyMethod("immediate"))},
	} {
		t.Run(value(rejected.ParameterName)+value(rejected.ParameterValue), func(t *testing.T) {
			now := time.Date(2031, 1, 1, 0, 0, 0, 0, time.UTC)
			s := New(Config{Clock: clock.NewManual(now)})
			t.Cleanup(func() { _ = s.Close() })
			v := retainedDatabase(now)
			v.Status, v.Operation, v.ParameterGroup = "available", "", "configured"
			seedDatabase(t, s, v)
			ctx := awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: v.Key.Partition, AccountID: v.Key.AccountID, Region: v.Key.Region, PrincipalARN: "arn:aws:iam::111111111111:root"})
			group := ParameterGroup{Key: Key{Scope: v.Key.Scope, Kind: "pg", Name: v.ParameterGroup}, Family: "postgres17", Parameters: map[string]string{"work_mem": "4MB"}}
			if err := s.repository.Update(ctx, func(tx Transaction) error { return tx.PutParameterGroup(group) }); err != nil {
				t.Fatal(err)
			}
			err := s.repository.Attempt(ctx, func(tx Transaction) error {
				_, err := s.changeParameters(ctx, tx, "pg", group.Key.Name, api.ParametersList{{ParameterName: new(api.String("work_mem")), ParameterValue: new(api.PotentiallySensitiveParameterValue("8MB")), ApplyMethod: new(api.ApplyMethod("immediate"))}, rejected}, false, false)
				return err
			})
			if err == nil {
				t.Fatal("unsupported batch was accepted")
			}
			if got := readDatabase(t, s, v.Key); got.Version != v.Version || got.Operation != "" {
				t.Fatalf("rejected batch queued native work: %#v", got)
			}
			if err := s.repository.View(ctx, func(r Reader) error {
				got, err := r.ParameterGroup(group.Key)
				if err == nil && got.Parameters["work_mem"] != "4MB" {
					t.Errorf("rejected batch retained earlier parameter: %#v", got)
				}
				return err
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestFailedParameterApplicationRemainsUnapplied(t *testing.T) {
	now := time.Date(2031, 1, 1, 0, 0, 0, 0, time.UTC)
	s := New(Config{Clock: clock.NewManual(now), Cipher: testCipher{}, Runtime: controlledRuntime{ensure: func(context.Context, engine.Specification) (engine.Endpoint, error) {
		return engine.Endpoint{}, errors.New("native parameter rejected")
	}}})
	t.Cleanup(func() { _ = s.Close() })
	v := retainedDatabase(now)
	v.Status, v.Operation = "modifying", "parameters"
	v.Parameters = map[string]string{"timezone": "unrecognized-native-zone"}
	seedDatabase(t, s, v)
	if err := (databaseJobs{s}).Run(t.Context(), selectDatabase(t, s)); err != nil {
		t.Fatal(err)
	}
	got := readDatabase(t, s, v.Key)
	if got.Status != "failed" || got.Endpoint.Address != "" || parameterStatus(got) == "in-sync" || got.Operation != "parameters" || !got.Due.After(now) {
		t.Fatalf("failed parameter application claimed successful publication: %#v", got)
	}
}
