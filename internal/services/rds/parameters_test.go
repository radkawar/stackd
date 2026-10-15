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
		{ParameterName: new(api.String("rds.force_ssl")), ParameterValue: new(api.PotentiallySensitiveParameterValue("2")), ApplyMethod: new(api.ApplyMethod("pending-reboot"))},
		{ParameterName: new(api.String("rds.force_ssl")), ParameterValue: new(api.PotentiallySensitiveParameterValue("on")), ApplyMethod: new(api.ApplyMethod("immediate"))},
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

func TestForceSSLDefaultsAndDeferredLifecycle(t *testing.T) {
	for _, eng := range []string{"postgres", "aurora-postgresql"} {
		t.Run(eng, func(t *testing.T) {
			now := time.Date(2031, 1, 1, 0, 0, 0, 0, time.UTC)
			manual := clock.NewManual(now)
			rejectNative := false
			observed := ""
			s := New(Config{Clock: manual, Cipher: testCipher{}, Runtime: controlledRuntime{ensure: func(_ context.Context, spec engine.Specification) (engine.Endpoint, error) {
				var ok bool
				observed, ok = spec.Parameters["rds.force_ssl"]
				if !ok {
					observed, _ = engine.DefaultParameter(spec.Engine, "rds.force_ssl")
				}
				if rejectNative {
					return engine.Endpoint{}, errors.New("native policy application failed")
				}
				return engine.Endpoint{Address: "127.0.0.1", Port: 15432, CA: []byte("owned-public-ca")}, nil
			}}})
			t.Cleanup(func() { _ = s.Close() })
			v := retainedDatabase(now)
			v.Engine, v.Status, v.Operation, v.ParameterGroup = eng, "available", "", "configured"
			kind := "pg"
			if eng == "aurora-postgresql" {
				v.Key.Kind, kind = "cluster", "cluster-pg"
			}
			seedDatabase(t, s, v)
			ctx := awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: v.Key.Partition, AccountID: v.Key.AccountID, Region: v.Key.Region, PrincipalARN: "arn:aws:iam::111111111111:root"})
			group := ParameterGroup{Key: Key{Scope: v.Key.Scope, Kind: kind, Name: v.ParameterGroup}, Family: engineFamily(eng), Parameters: map[string]string{}, ApplyMethods: map[string]string{}}
			if err := s.repository.Update(ctx, func(tx Transaction) error { return tx.PutParameterGroup(group) }); err != nil {
				t.Fatal(err)
			}
			checkProjection := func(source, expected, origin string) {
				t.Helper()
				if err := s.repository.View(ctx, func(r Reader) error {
					parameters, marker, err := s.readParameters(ctx, r, kind, group.Key.Name, source, nil, nil, nil)
					if err != nil {
						return err
					}
					if expected == "" {
						if len(parameters) != 0 {
							t.Fatalf("unexpected %s catalog: %#v", source, parameters)
						}
						return nil
					}
					if len(parameters) != 1 || marker != nil {
						t.Fatalf("wrong supported catalog: %#v", parameters)
					}
					p := parameters[0]
					if value(p.ParameterName) != "rds.force_ssl" || value(p.ParameterValue) != expected || value(p.Source) != origin || value(p.ApplyType) != "dynamic" || value(p.DataType) != "boolean" || value(p.AllowedValues) != "0,1" {
						t.Fatalf("wrong force_ssl projection: %#v", p)
					}
					if value(p.ApplyMethod) != "pending-reboot" {
						t.Fatalf("wrong default or deferred apply method: %#v", p)
					}
					return nil
				}); err != nil {
					t.Fatal(err)
				}
			}
			change := func(reset bool) {
				t.Helper()
				if err := s.repository.Update(ctx, func(tx Transaction) error {
					_, err := s.changeParameters(ctx, tx, kind, group.Key.Name, api.ParametersList{{ParameterName: new(api.String("rds.force_ssl")), ParameterValue: new(api.PotentiallySensitiveParameterValue("0")), ApplyMethod: new(api.ApplyMethod("pending-reboot"))}}, reset, false)
					return err
				}); err != nil {
					t.Fatal(err)
				}
			}
			reboot := func() {
				t.Helper()
				if err := s.repository.Update(ctx, func(tx Transaction) error {
					_, err := s.transition(ctx, tx, "RebootDBInstance", v.Key.Kind, v.Key.Name, "reboot")
					return err
				}); err != nil {
					t.Fatal(err)
				}
			}
			checkProjection("", "1", "system")
			checkProjection("system", "1", "system")
			checkProjection("engine-default", "", "")
			checkProjection("user", "", "")
			change(false)
			checkProjection("user", "0", "user")
			checkProjection("engine-default", "", "")
			if got := readDatabase(t, s, v.Key); got.Status != "available" || !got.PendingParameters || got.Parameters["rds.force_ssl"] != "" {
				t.Fatalf("deferred mutation prematurely changed active generation: %#v", got)
			}
			if err := (databaseJobs{s}).Run(ctx, selectDatabase(t, s)); err != nil {
				t.Fatal(err)
			}
			if got := readDatabase(t, s, v.Key); observed != "1" || !got.PendingParameters {
				t.Fatalf("periodic reconciliation applied deferred policy: observed=%s state=%#v", observed, got)
			}
			reboot()
			rejectNative = true
			if err := (databaseJobs{s}).Run(ctx, selectDatabase(t, s)); err != nil {
				t.Fatal(err)
			}
			got := readDatabase(t, s, v.Key)
			if observed != "0" || got.Status != "failed" || !got.PendingParameters || got.Operation != "reboot" || instanceDTO(got).Endpoint != nil {
				t.Fatalf("failed native policy claimed completion: observed=%s state=%#v", observed, got)
			}
			rejectNative = false
			manual.Advance(healthInterval)
			if err := (databaseJobs{s}).Run(ctx, selectDatabase(t, s)); err != nil {
				t.Fatal(err)
			}
			if got := readDatabase(t, s, v.Key); got.Status != "available" || got.PendingParameters || got.Parameters["rds.force_ssl"] != "0" {
				t.Fatalf("completed reboot lost active policy: %#v", got)
			}
			change(true)
			checkProjection("", "1", "system")
			if got := readDatabase(t, s, v.Key); !got.PendingParameters || got.Parameters["rds.force_ssl"] != "0" {
				t.Fatalf("reset prematurely changed active policy: %#v", got)
			}
			reboot()
			if err := (databaseJobs{s}).Run(ctx, selectDatabase(t, s)); err != nil {
				t.Fatal(err)
			}
			if got := readDatabase(t, s, v.Key); observed != "1" || got.Status != "available" || got.PendingParameters {
				t.Fatalf("reset reboot did not enforce default: observed=%s state=%#v", observed, got)
			}
		})
	}
}

func TestForceSSLDefaultEquivalenceAndMySQLBoundary(t *testing.T) {
	for _, eng := range []string{"postgres", "aurora-postgresql"} {
		if !parametersEqual(eng, nil, map[string]string{"rds.force_ssl": "1"}) || parametersEqual(eng, nil, map[string]string{"rds.force_ssl": "0"}) {
			t.Fatalf("%s omission does not resolve to the pinned default", eng)
		}
	}
	for _, eng := range []string{"mysql", "aurora-mysql"} {
		if err := validateParameter(eng, api.Parameter{ParameterName: new(api.String("rds.force_ssl")), ParameterValue: new(api.PotentiallySensitiveParameterValue("1")), ApplyMethod: new(api.ApplyMethod("pending-reboot"))}, false); err == nil {
			t.Fatalf("%s accepted a PostgreSQL-only policy", eng)
		}
		if _, ok := engine.DefaultParameter(eng, "rds.force_ssl"); ok {
			t.Fatalf("%s advertises a PostgreSQL-only default", eng)
		}
	}
}

func TestForceSSLImmediateWaitsForNativeCompletion(t *testing.T) {
	for _, eng := range []string{"postgres", "aurora-postgresql"} {
		t.Run(eng, func(t *testing.T) {
			now := time.Date(2031, 1, 1, 0, 0, 0, 0, time.UTC)
			manual := clock.NewManual(now)
			rejectNative := true
			wantPolicy := "0"
			var s *Service
			var key Key
			s = New(Config{Clock: manual, Cipher: testCipher{}, Runtime: controlledRuntime{ensure: func(_ context.Context, spec engine.Specification) (engine.Endpoint, error) {
				got := readDatabase(t, s, key)
				if got.Status == "available" || got.Operation != "parameters" || instanceDTO(got).Endpoint != nil {
					t.Fatalf("policy was exposed before native completion: %#v", got)
				}
				policy, ok := spec.Parameters["rds.force_ssl"]
				if !ok {
					policy, _ = engine.DefaultParameter(spec.Engine, "rds.force_ssl")
				}
				if policy != wantPolicy || spec.Parameters["max_connections"] != "100" {
					t.Fatalf("wrong immediate native generation: %#v", spec.Parameters)
				}
				if rejectNative {
					return engine.Endpoint{}, errors.New("native reload rejected")
				}
				return engine.Endpoint{Address: "127.0.0.1", Port: 15432, CA: []byte("owned-public-ca")}, nil
			}}})
			t.Cleanup(func() { _ = s.Close() })
			v := retainedDatabase(now)
			v.Engine, v.Status, v.Operation, v.ParameterGroup = eng, "available", "", "configured"
			v.Parameters = map[string]string{"max_connections": "100"}
			kind := "pg"
			if eng == "aurora-postgresql" {
				v.Key.Kind, kind = "cluster", "cluster-pg"
			}
			key = v.Key
			seedDatabase(t, s, v)
			ctx := awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: v.Key.Partition, AccountID: v.Key.AccountID, Region: v.Key.Region, PrincipalARN: "arn:aws:iam::111111111111:root"})
			group := ParameterGroup{Key: Key{Scope: v.Key.Scope, Kind: kind, Name: v.ParameterGroup}, Family: engineFamily(eng), Parameters: map[string]string{"max_connections": "150"}, ApplyMethods: map[string]string{"max_connections": "pending-reboot"}}
			if err := s.repository.Update(ctx, func(tx Transaction) error { return tx.PutParameterGroup(group) }); err != nil {
				t.Fatal(err)
			}
			change := func(reset bool) {
				t.Helper()
				if err := s.repository.Update(ctx, func(tx Transaction) error {
					_, err := s.changeParameters(ctx, tx, kind, group.Key.Name, api.ParametersList{{ParameterName: new(api.String("rds.force_ssl")), ParameterValue: new(api.PotentiallySensitiveParameterValue("0")), ApplyMethod: new(api.ApplyMethod("immediate"))}}, reset, false)
					return err
				}); err != nil {
					t.Fatal(err)
				}
			}
			change(false)
			if got := readDatabase(t, s, key); got.Status != "modifying" || got.Operation != "parameters" || !got.PendingParameters {
				t.Fatalf("immediate policy failed to queue native work: %#v", got)
			}
			if err := (databaseJobs{s}).Run(ctx, selectDatabase(t, s)); err != nil {
				t.Fatal(err)
			}
			if got := readDatabase(t, s, key); got.Status != "failed" || got.Operation != "parameters" || parameterStatus(got) == "in-sync" {
				t.Fatalf("native reload failure claimed success: %#v", got)
			}
			rejectNative = false
			manual.Advance(healthInterval)
			if err := (databaseJobs{s}).Run(ctx, selectDatabase(t, s)); err != nil {
				t.Fatal(err)
			}
			if got := readDatabase(t, s, key); got.Status != "available" || !got.PendingParameters || got.Parameters["rds.force_ssl"] != "0" || len(got.Endpoint.CA) == 0 {
				t.Fatalf("native completion lost policy/trust/deferred settings: %#v", got)
			}
			wantPolicy = "1"
			change(true)
			if err := (databaseJobs{s}).Run(ctx, selectDatabase(t, s)); err != nil {
				t.Fatal(err)
			}
			if got := readDatabase(t, s, key); got.Status != "available" || !got.PendingParameters {
				t.Fatalf("default reset discarded unrelated pending reboot: %#v", got)
			}
		})
	}
}
