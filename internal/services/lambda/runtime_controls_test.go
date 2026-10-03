package lambda

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	api "stackd/internal/awsapi/lambda"
	"stackd/internal/awsctx"
)

func TestProvisionedCapacityReservationRollback(t *testing.T) {
	ctx := context.Background()
	repository := NewMemoryRepository(nil)
	key := FunctionKey{Scope: Scope{Partition: "aws", Account: "123456789012", Region: "us-east-1"}, Name: "capacity"}
	ref := FunctionReference{FunctionKey: key, Qualifier: "1"}
	if err := repository.Update(ctx, func(tx Transaction) error {
		if err := tx.PutFunction(FunctionRecord{Key: key}); err != nil {
			return err
		}
		if err := tx.PutProvisionedConcurrency(ProvisionedConcurrencyRecord{Key: ref, Requested: 900}); err != nil {
			return err
		}
		return validateProvisionedReservations(tx, key)
	}); err != nil {
		t.Fatal(err)
	}
	// A second enormous request must not wrap an int32 aggregate and evade the
	// account limit. The rejected transaction must retain the previous capacity.
	err := repository.Update(ctx, func(tx Transaction) error {
		if err := tx.PutProvisionedConcurrency(ProvisionedConcurrencyRecord{Key: FunctionReference{FunctionKey: key, Qualifier: "2"}, Requested: 2147483647}); err != nil {
			return err
		}
		return validateProvisionedReservations(tx, key)
	})
	if err == nil || wireError(err).Code != "InvalidParameterValueException" {
		t.Fatalf("overflow admission = %v", err)
	}
	if err := repository.View(ctx, func(r Reader) error {
		rows, err := r.AllProvisionedConcurrency()
		if err != nil {
			return err
		}
		if len(rows) != 1 || rows[0].Key != ref || rows[0].Requested != 900 {
			t.Fatalf("rejected capacity changed retained reservation: %+v", rows)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := repository.Update(ctx, func(tx Transaction) error {
		if err := tx.PutFunctionConcurrency(key, 899); err != nil {
			return err
		}
		return validateProvisionedReservations(tx, key)
	}); err == nil {
		t.Fatal("reserved concurrency admitted below provisioned capacity")
	}
}

func TestRecursionConfigurationChangesAdmission(t *testing.T) {
	repository := NewMemoryRepository(nil)
	s := New(Config{Repository: repository})
	t.Cleanup(func() {
		if err := s.Close(); err != nil {
			t.Error(err)
		}
	})
	key := FunctionKey{Scope: Scope{Partition: "aws", Account: "123456789012", Region: "us-east-1"}, Name: "recursive"}
	if err := repository.Update(context.Background(), func(tx Transaction) error { return tx.PutFunction(FunctionRecord{Key: key}) }); err != nil {
		t.Fatal(err)
	}
	// Start from the native-observed fifteenth execution. The leading lineage
	// count is 15, not a fixed version marker; the next execution is still legal.
	trace := "Root=1-6aba3a9c-0ad723aa6f28be0c1799046b;Sampled=0;Lineage=15:" + recursionResource(key) + ":14"
	for invocation := 16; invocation <= 17; invocation++ {
		ctx := awsctx.WithMetadata(context.Background(), awsctx.Metadata{TraceHeader: trace})
		err := repository.View(ctx, func(r Reader) error {
			_, wire := s.admitInvocation(r, FunctionVersionKey{FunctionKey: key}, FunctionReference{FunctionKey: key})
			if invocation <= 16 {
				if wire != nil {
					t.Fatalf("invocation %d rejected: %v", invocation, wire)
				}
				s.releaseInvocationLocked(key, nil)
			} else if wire == nil || wire.Code != "RecursiveInvocationException" {
				t.Fatalf("recursive chain escaped protection: %v", wire)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		if invocation <= 16 {
			trace = recursionTrace(trace, key, time.Unix(1, 0))
		}
	}
	if err := repository.Update(context.Background(), func(tx Transaction) error { return tx.PutRecursiveLoop(key, "Allow") }); err != nil {
		t.Fatal(err)
	}
	ctx := awsctx.WithMetadata(context.Background(), awsctx.Metadata{TraceHeader: trace})
	if err := repository.View(ctx, func(r Reader) error {
		if _, wire := s.admitInvocation(r, FunctionVersionKey{FunctionKey: key}, FunctionReference{FunctionKey: key}); wire != nil {
			t.Fatalf("Allow did not change admission: %v", wire)
		}
		s.releaseInvocationLocked(key, nil)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := repository.Update(context.Background(), func(tx Transaction) error { return tx.PutRecursiveLoop(key, "Terminate") }); err != nil {
		t.Fatal(err)
	}
	if err := repository.View(context.Background(), func(r Reader) error {
		if _, wire := s.admitInvocation(r, FunctionVersionKey{FunctionKey: key}, FunctionReference{FunctionKey: key}); wire != nil {
			t.Fatalf("independent request inherited another chain: %v", wire)
		}
		s.releaseInvocationLocked(key, nil)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestProvisionedReservationDoesNotFundOnDemandQualifier(t *testing.T) {
	repository := NewMemoryRepository(nil)
	s := New(Config{Repository: repository})
	key := FunctionKey{Scope: Scope{Partition: "aws", Account: "123456789012", Region: "us-east-1"}, Name: "qualified"}
	held := 0
	t.Cleanup(func() {
		for range held {
			s.releaseInvocationLocked(key, nil)
		}
		if err := s.Close(); err != nil {
			t.Error(err)
		}
	})
	ctx := context.Background()
	if err := repository.Update(ctx, func(tx Transaction) error {
		if err := tx.PutFunction(FunctionRecord{Key: key}); err != nil {
			return err
		}
		return tx.PutProvisionedConcurrency(ProvisionedConcurrencyRecord{Key: FunctionReference{FunctionKey: key, Qualifier: "1"}, Requested: 900, Status: "IN_PROGRESS"})
	}); err != nil {
		t.Fatal(err)
	}
	if err := repository.View(ctx, func(r Reader) error {
		// Version 1 reserves 900 executions, but these unqualified requests
		// require on-demand environments. Only the remaining 100 are theirs.
		for range 100 {
			if _, wire := s.admitInvocation(r, FunctionVersionKey{FunctionKey: key}, FunctionReference{FunctionKey: key}); wire != nil {
				t.Fatalf("unreserved capacity rejected early: %v", wire)
			}
			held++
		}
		if _, wire := s.admitInvocation(r, FunctionVersionKey{FunctionKey: key}, FunctionReference{FunctionKey: key}); wire == nil || wire.Code != "TooManyRequestsException" {
			t.Fatalf("on-demand invocation borrowed another qualifier's reservation: %v", wire)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestAliasConsumesNumericVersionPoolWithoutBorrowingAliasCapacity(t *testing.T) {
	repository := NewMemoryRepository(nil)
	s := New(Config{Repository: repository})
	key := FunctionKey{Scope: Scope{Partition: "aws", Account: "123456789012", Region: "us-east-1"}, Name: "qualified"}
	version := FunctionVersionKey{FunctionKey: key, Version: 1}
	numeric := FunctionReference{FunctionKey: key, Qualifier: "1"}
	alias := FunctionReference{FunctionKey: key, Qualifier: "live"}
	slot := &execution{key: version, provisioned: numeric, provisionedGeneration: "pool", provisionedReady: true}
	s.environments[version] = []*execution{slot}
	t.Cleanup(func() {
		delete(s.environments, version)
		if err := s.Close(); err != nil {
			t.Error(err)
		}
	})
	if err := repository.Update(t.Context(), func(tx Transaction) error {
		if err := tx.PutFunction(FunctionRecord{Key: key}); err != nil {
			return err
		}
		return tx.PutProvisionedConcurrency(ProvisionedConcurrencyRecord{Key: numeric, Requested: 900, Status: "READY", Generation: "pool"})
	}); err != nil {
		t.Fatal(err)
	}
	if err := repository.View(t.Context(), func(r Reader) error {
		// Exhaust on-demand capacity: the alias must use the numeric pool,
		// charge that pool, and release the same accounting identity.
		for range 100 {
			if _, wire := s.admitInvocation(r, FunctionVersionKey{FunctionKey: key}, FunctionReference{FunctionKey: key}); wire != nil {
				t.Fatal(wire)
			}
		}
		defer func() {
			for range 100 {
				s.releaseInvocationLocked(key, nil)
			}
		}()
		if _, wire := s.admitInvocation(r, version, alias); wire != nil {
			t.Fatalf("alias could not consume its version's idle provisioned environment: %v", wire)
		}
		leased := s.invocationExecutionLocked(version, alias)
		if leased != slot || !slot.leased {
			t.Fatal("admission did not lease the provisioned environment")
		}
		usage := s.inFlight[key.Scope].functions[key.Name]
		if usage.provisioned["1"] != 1 || usage.provisioned["live"] != 0 {
			t.Fatalf("capacity charged to requested alias rather than owning pool: %v", usage.provisioned)
		}
		if _, wire := s.admitInvocation(r, version, numeric); wire == nil || wire.Code != "TooManyRequestsException" {
			t.Fatalf("busy pool allowed on-demand spillover beyond the account limit: %v", wire)
		}
		s.releaseInvocationLocked(key, leased)
		slot.leased = false
		if len(usage.provisioned) != 0 {
			t.Fatalf("pool credit leaked after alias release: %v", usage.provisioned)
		}
		slot.provisioned = FunctionReference{FunctionKey: key, Qualifier: "other"}
		if s.provisionedExecutionLocked(version, alias) != nil || s.provisionedExecutionLocked(version, numeric) != nil {
			t.Fatal("invocation borrowed another alias's pool")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestAliasRoutingRestartsProvisionedReadiness(t *testing.T) {
	for _, status := range []string{"READY", "FAILED"} {
		for _, change := range []string{"primary", "weight", "description"} {
			t.Run(status+"/"+change, func(t *testing.T) {
				repository := NewMemoryRepository(nil)
				ctx, ref := aliasOwnerFixture(t, repository)
				s := aliasOwnerService(t, Config{Repository: repository})
				create := aliasOwnerCreate(ref)
				if _, wire := s.createAlias(ctx, create); wire != nil {
					t.Fatal(wire)
				}
				pool := ProvisionedConcurrencyRecord{Key: ref, Requested: 2, Generation: "previous-initialization", Status: status, Modified: time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)}
				if status == "FAILED" {
					pool.StatusReason = "previous target initialization failed"
				}
				if err := repository.Update(ctx, func(tx Transaction) error { return tx.PutProvisionedConcurrency(pool) }); err != nil {
					t.Fatal(err)
				}
				// Keep old ready slots in memory; the worker has not reconciled
				// routing yet, so counts alone cannot establish new readiness.
				first := FunctionVersionKey{FunctionKey: ref.FunctionKey, Version: 1}
				second := FunctionVersionKey{FunctionKey: ref.FunctionKey, Version: 2}
				s.environments[first] = []*execution{
					{key: first, provisioned: ref, provisionedGeneration: pool.Generation, provisionedReady: true},
					{key: first, provisioned: ref, provisionedGeneration: pool.Generation, provisionedReady: true},
				}
				s.environments[second] = []*execution{{key: second, provisioned: ref, provisionedGeneration: pool.Generation, provisionedReady: true}}
				get := &api.GetProvisionedConcurrencyConfigInput{FunctionName: create.FunctionName, Qualifier: new(api.Qualifier(ref.Qualifier))}
				before, wire := s.getProvisionedConcurrencyConfig(ctx, get)
				if wire != nil || value(before.Status) != status {
					t.Fatalf("initial pool status: %+v %v", before, wire)
				}
				update := &api.UpdateAliasInput{FunctionName: create.FunctionName, Name: create.Name}
				switch change {
				case "primary":
					update.FunctionVersion = new(api.VersionWithLatestPublished("2"))
					update.RoutingConfig = &api.AliasRoutingConfiguration{}
				case "weight":
					update.RoutingConfig = &api.AliasRoutingConfiguration{AdditionalVersionWeights: api.AdditionalVersionWeights{"2": 0.75}}
				case "description":
					update.Description = new(api.Description("metadata only"))
				}
				abort := errors.New("abort alias retarget")
				if err := repository.Update(ctx, func(tx Transaction) error {
					if _, wire := s.updateAlias(tx.Context(), update); wire != nil {
						return wire
					}
					return abort
				}); !errors.Is(err, abort) {
					t.Fatalf("retarget rollback: %v", err)
				}
				rolledBack, wire := s.getProvisionedConcurrencyConfig(ctx, get)
				if wire != nil || !reflect.DeepEqual(rolledBack, before) {
					t.Fatalf("rolled-back routing changed provisioned state: %+v %v; want %+v", rolledBack, wire, before)
				}
				if _, wire := s.updateAlias(ctx, update); wire != nil {
					t.Fatal(wire)
				}
				current, wire := s.getProvisionedConcurrencyConfig(ctx, get)
				if change == "description" {
					if wire != nil || !reflect.DeepEqual(current, before) {
						t.Fatalf("description-only update restarted the pool: %+v %v; want %+v", current, wire, before)
					}
					return
				}
				if wire != nil || value(current.Status) != "IN_PROGRESS" || current.StatusReason != nil || *current.RequestedProvisionedConcurrentExecutions != 2 {
					t.Fatalf("retarget reused old readiness or failure: %+v %v", current, wire)
				}
				for _, lateResult := range []error{nil, errors.New("late old-target failure")} {
					if err := s.finishProvisioned(pool, lateResult); err != nil {
						t.Fatal(err)
					}
					current, wire = s.getProvisionedConcurrencyConfig(ctx, get)
					if wire != nil || value(current.Status) != "IN_PROGRESS" || current.StatusReason != nil {
						t.Fatalf("stale worker completed new routing: %+v %v", current, wire)
					}
				}
				// Only initialization for the retained current request can
				// complete readiness after the new target slots are present.
				var replacement ProvisionedConcurrencyRecord
				if err := repository.View(ctx, func(r Reader) error {
					var err error
					replacement, err = r.ProvisionedConcurrency(ref)
					if err != nil {
						return err
					}
					targets, err := provisionedTargets(r, replacement)
					if err != nil {
						return err
					}
					for _, target := range targets {
						key := FunctionVersionKey{FunctionKey: ref.FunctionKey, Version: target.function.Version}
						for range target.count {
							s.environments[key] = append(s.environments[key], &execution{key: key, provisioned: ref, provisionedGeneration: replacement.Generation, provisionedReady: true})
						}
					}
					return nil
				}); err != nil {
					t.Fatal(err)
				}
				if err := s.finishProvisioned(replacement, nil); err != nil {
					t.Fatal(err)
				}
				current, wire = s.getProvisionedConcurrencyConfig(ctx, get)
				if wire != nil || value(current.Status) != "READY" || current.StatusReason != nil {
					t.Fatalf("current-target initialization did not restore readiness: %+v %v", current, wire)
				}
			})
		}
	}
}
