package lambda

import (
	"context"
	"errors"
	"fmt"
	"testing"

	api "stackd/internal/awsapi/lambda"
	"stackd/internal/awsctx"
)

func managedLifecycleScope(t *testing.T) (context.Context, FunctionKey) {
	t.Helper()
	scope := Scope{Partition: "aws", Account: "111111111111", Region: "us-east-1"}
	return awsctx.WithMetadata(t.Context(), awsctx.Metadata{Partition: scope.Partition, AccountID: scope.Account, Region: scope.Region, PrincipalARN: "arn:aws:iam::111111111111:root", PrincipalID: scope.Account}), FunctionKey{Scope: scope, Name: "retained-capacity"}
}

func TestManagedPublicationQuotaPreservesMutableSnapshot(t *testing.T) {
	ctx, key := managedLifecycleScope(t)
	repository := NewMemoryRepository(nil)
	latest := FunctionRecord{Key: key, State: "Active", DeploymentRevision: "unpublished", Capacity: &CapacityFunctionConfig{ProviderARN: (CapacityProviderKey{Scope: key.Scope, Name: "provider"}).ARN()}}
	if err := repository.Update(ctx, func(tx Transaction) error {
		if err := tx.PutFunction(latest); err != nil {
			return err
		}
		for i := 1; i <= 99; i++ {
			version, err := tx.AllocateFunctionVersion(key)
			if err != nil {
				return err
			}
			published := latest
			published.Version = version
			published.DeploymentRevision = fmt.Sprint(i)
			if err = tx.PutFunctionVersion(published); err != nil {
				return err
			}
		}
		_, _, err := publishCapacitySnapshot(tx, latest, nil)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	err := repository.Update(ctx, func(tx Transaction) error { _, _, err := publishSnapshot(tx, latest, nil); return err })
	if err == nil || wireError(err).Code != "FunctionVersionsPerCapacityProviderLimitExceededException" {
		t.Fatalf("101st version admission = %v", err)
	}
	if err = repository.Update(ctx, func(tx Transaction) error {
		latest.DeploymentRevision = "replacement"
		published, created, err := publishCapacitySnapshot(tx, latest, nil)
		if err != nil {
			return err
		}
		if !created || published.Version != LatestPublishedVersion || published.DeploymentRevision != "replacement" {
			t.Fatalf("mutable publication was not replaced: %+v", published)
		}
		unchanged := latest
		unchanged.DeploymentRevision = "99"
		published, created, err = publishSnapshot(tx, unchanged, nil)
		if err != nil {
			return err
		}
		if created || published.Version != 99 {
			t.Fatalf("unchanged publication allocated capacity: version=%d created=%v", published.Version, created)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err = repository.Update(ctx, func(tx Transaction) error {
		versions, err := capacityVersions(tx, CapacityProviderKey{Scope: key.Scope, Name: "provider"})
		if err != nil {
			return err
		}
		if len(versions) != 100 {
			t.Fatalf("provider retained %d versions after rejection/replacement; want exact quota", len(versions))
		}
		if err = tx.DeleteFunctionVersion(FunctionVersionKey{FunctionKey: key, Version: 1}); err != nil {
			return err
		}
		published, created, err := publishSnapshot(tx, latest, nil)
		if err != nil {
			return err
		}
		if !created || published.Version != 100 {
			t.Fatalf("released capacity or version allocation was lost: version=%d created=%v", published.Version, created)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestManagedFunctionDeletionDoesNotInheritDeactivation(t *testing.T) {
	ctx, key := managedLifecycleScope(t)
	repository := NewMemoryRepository(nil)
	service := New(Config{Repository: repository})
	t.Cleanup(func() {
		if err := service.Close(); err != nil {
			t.Error(err)
		}
	})
	function := FunctionRecord{Key: key, State: "Active", DeploymentRevision: "original", Capacity: &CapacityFunctionConfig{ProviderARN: (CapacityProviderKey{Scope: key.Scope, Name: "provider"}).ARN()}}
	otherKey := key
	otherKey.Name = "unrelated"
	first := FunctionReference{FunctionKey: key, Qualifier: "1"}
	second := FunctionReference{FunctionKey: key, Qualifier: "2"}
	unrelated := FunctionReference{FunctionKey: otherKey, Qualifier: "1"}
	latest := FunctionReference{FunctionKey: key, Qualifier: "$LATEST.PUBLISHED"}
	if err := repository.Update(ctx, func(tx Transaction) error {
		if err := tx.PutFunction(function); err != nil {
			return err
		}
		for _, version := range []uint64{1, 2} {
			published := function
			published.Version = version
			if err := tx.PutFunctionVersion(published); err != nil {
				return err
			}
		}
		published := function
		published.Version = LatestPublishedVersion
		if err := tx.ReplaceCapacityPublishedFunction(published); err != nil {
			return err
		}
		for _, ref := range []FunctionReference{first, second, latest, unrelated} {
			if err := tx.PutCapacityScaling(CapacityScalingRecord{Key: ref, Generation: "original", MinEnvironments: 0, MaxEnvironments: 0}); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, wire := service.deleteFunction(ctx, &api.DeleteFunctionInput{FunctionName: new(api.NamespacedFunctionName(key.Name)), Qualifier: new(api.NumericLatestPublishedOrAliasQualifier("$LATEST.PUBLISHED"))}); wire != nil {
		t.Fatal(wire)
	}
	if err := repository.View(ctx, func(r Reader) error {
		if _, err := r.CapacityScaling(latest); !errors.Is(err, ErrNotFound) {
			t.Fatalf("deleted mutable publication retained scaling: %v", err)
		}
		if _, err := r.Function(key); err != nil {
			return err
		}
		if _, err := selectFunction(r, FunctionReference{FunctionKey: key}, "after-deletion", 0); err == nil || wireError(err).Code != "NoPublishedVersionException" {
			t.Fatalf("deleted mutable publication remained invokable: %v", err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, wire := service.deleteFunction(ctx, &api.DeleteFunctionInput{FunctionName: new(api.NamespacedFunctionName(key.Name)), Qualifier: new(api.NumericLatestPublishedOrAliasQualifier("1"))}); wire != nil {
		t.Fatal(wire)
	}
	if err := repository.View(ctx, func(r Reader) error {
		if _, err := r.CapacityScaling(first); !errors.Is(err, ErrNotFound) {
			t.Fatalf("deleted version retained scaling: %v", err)
		}
		if _, err := r.CapacityScaling(second); err != nil {
			t.Fatalf("version deletion changed sibling scaling: %v", err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, wire := service.deleteFunction(ctx, &api.DeleteFunctionInput{FunctionName: new(api.NamespacedFunctionName(key.Name))}); wire != nil {
		t.Fatal(wire)
	}
	if err := repository.Update(ctx, func(tx Transaction) error {
		function.DeploymentRevision = "recreated"
		if err := tx.PutFunction(function); err != nil {
			return err
		}
		function.Version = 1
		return tx.PutFunctionVersion(function)
	}); err != nil {
		t.Fatal(err)
	}
	out, wire := service.getCapacityScaling(ctx, &api.GetFunctionScalingConfigRequest{FunctionName: new(api.UnqualifiedFunctionName(key.Name)), Qualifier: new(api.PublishedFunctionQualifier("1"))})
	if wire != nil {
		t.Fatal(wire)
	}
	if out.RequestedFunctionScalingConfig == nil || out.RequestedFunctionScalingConfig.MaxExecutionEnvironments == nil || *out.RequestedFunctionScalingConfig.MaxExecutionEnvironments == 0 {
		t.Fatal("recreated function inherited the previous incarnation's deactivation")
	}
	if err := repository.View(ctx, func(r Reader) error {
		if _, err := r.CapacityScaling(second); !errors.Is(err, ErrNotFound) {
			t.Fatalf("base deletion retained sibling version scaling: %v", err)
		}
		retained, err := r.CapacityScaling(unrelated)
		if err != nil {
			return err
		}
		if retained.Generation != "original" || retained.MaxEnvironments != 0 {
			t.Fatalf("unrelated scaling changed: %+v", retained)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
