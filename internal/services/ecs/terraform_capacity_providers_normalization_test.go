package ecs

import (
	"reflect"
	"testing"

	api "stackd/internal/awsapi/ecs"
)

func TestPutClusterCapacityProvidersNormalizesExecutableDefaults(t *testing.T) {
	s, repository, ctx, key := capacityProviderTestCluster(t)
	in := fargateCapacityProviderUpdate(key)
	in.DefaultCapacityProviderStrategy[0].Base = nil
	out, rejected := putTestCapacityProviders(s, ctx, in)
	if rejected != nil || out.Cluster.DefaultCapacityProviderStrategy[0].Base == nil || *out.Cluster.DefaultCapacityProviderStrategy[0].Base != 0 || in.DefaultCapacityProviderStrategy[0].Base != nil {
		t.Fatalf("normalization=%+v rejected=%v", out, rejected)
	}
	// Nonzero base and the AWS numeric boundaries still select the real single
	// provider, rather than silently dropping a valid strategy during refresh.
	in.DefaultCapacityProviderStrategy[0].Base = new(api.CapacityProviderStrategyItemBase(100000))
	in.DefaultCapacityProviderStrategy[0].Weight = new(api.CapacityProviderStrategyItemWeight(1000))
	if _, rejected := putTestCapacityProviders(s, ctx, in); rejected != nil {
		t.Fatal(rejected)
	}
	if err := repository.View(ctx, func(r Reader) error {
		record, err := r.Cluster(key)
		if err != nil {
			return err
		}
		if !reflect.DeepEqual(record.Data.DefaultCapacityProviderStrategy, in.DefaultCapacityProviderStrategy) {
			t.Fatal("valid base and weight were not persisted")
		}
		launch, provider, rejected := taskLaunchType(&api.RunTaskInput{}, record.Data)
		if rejected != nil || launch != "FARGATE" || provider != "FARGATE" {
			t.Fatalf("normalized launch=%s provider=%s rejected=%v", launch, provider, rejected)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
