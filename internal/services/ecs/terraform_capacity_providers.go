package ecs

import (
	"context"
	"errors"
	"slices"

	api "stackd/internal/awsapi/ecs"
)

// putClusterCapacityProviders updates the same cluster state used by RunTask and
// CreateService. Only FARGATE is executable: SPOT interruption and custom Auto
// Scaling capacity lifecycles are not implemented, even as empty associations.
func (s *Service) putClusterCapacityProviders(ctx context.Context, tx Transaction, in *api.PutClusterCapacityProvidersInput) (*api.PutClusterCapacityProvidersOutput, error) {
	key, rejected := clusterKey(ctx, value(in.Cluster))
	if rejected != nil {
		return nil, rejected
	}
	tags, err := tagsFor(tx, key.Scope, key.ARN())
	if err != nil {
		return nil, err
	}
	conditions := map[string][]string{}
	for _, provider := range in.CapacityProviders {
		conditions["ecs:capacity-provider"] = append(conditions["ecs:capacity-provider"], string(provider))
	}
	if err := s.authorize(ctx, "PutClusterCapacityProviders", key.ARN(), tags, conditions); err != nil {
		return nil, err
	}
	record, err := tx.Cluster(key)
	if errors.Is(err, ErrNotFound) {
		return nil, failure("ClusterNotFoundException", "Cluster not found.")
	}
	if err != nil {
		return nil, err
	}
	if value(record.Data.Status) != "ACTIVE" {
		return nil, failure("ClientException", "Cluster was not ACTIVE.")
	}
	admitted := api.CreateClusterInput{
		CapacityProviders:               api.CloneStringList(in.CapacityProviders),
		DefaultCapacityProviderStrategy: api.CloneCapacityProviderStrategy(in.DefaultCapacityProviderStrategy),
	}
	if len(admitted.CapacityProviders) > 20 || len(admitted.DefaultCapacityProviderStrategy) > 20 {
		return nil, failure("InvalidParameterException", "Capacity providers and strategies can have at most 20 entries.")
	}
	for i, provider := range admitted.CapacityProviders {
		if slices.Contains(admitted.CapacityProviders[:i], provider) {
			return nil, failure("InvalidParameterException", "A capacity provider may only be associated once.")
		}
	}
	if err := normalizeCapacityProviders(&admitted); err != nil {
		return nil, err
	}
	if slices.Contains(admitted.CapacityProviders, api.String("FARGATE_SPOT")) {
		return nil, unsupported("FARGATE_SPOT requires its real capacity and interruption lifecycle.")
	}
	if err := validateServiceCapacity(admitted.DefaultCapacityProviderStrategy); err != nil {
		return nil, err
	}
	// An empty replacement clears defaults and associations. Explicit launch-type
	// tasks do not depend on an association; provider-backed tasks and live service
	// execution snapshots do, including draining services and rolling deployments.
	for _, provider := range record.Data.CapacityProviders {
		if !slices.Contains(admitted.CapacityProviders, provider) {
			if err := capacityProviderRemoval(tx, key, string(provider)); err != nil {
				return nil, err
			}
		}
	}
	if admitted.CapacityProviders == nil {
		admitted.CapacityProviders = api.StringList{}
	}
	if admitted.DefaultCapacityProviderStrategy == nil {
		admitted.DefaultCapacityProviderStrategy = api.CapacityProviderStrategy{}
	}
	record.Data.CapacityProviders = admitted.CapacityProviders
	record.Data.DefaultCapacityProviderStrategy = admitted.DefaultCapacityProviderStrategy
	if err := projectActiveServices(tx, key, &record.Data); err != nil {
		return nil, err
	}
	record.Updated = s.clock.Now()
	// CreateInput is deliberately unchanged: it retains creation idempotency.
	if err := tx.PutCluster(record); err != nil {
		return nil, err
	}
	data := api.CloneCluster(record.Data)
	data.Tags = api.Tags{}
	data.Attachments = api.Attachments{}
	return &api.PutClusterCapacityProvidersOutput{Cluster: &data}, nil
}

func capacityProviderRemoval(tx Transaction, key ClusterKey, provider string) error {
	tasks, err := tx.Tasks(TaskQuery{ClusterKey: key, ActiveOnly: true})
	if err != nil {
		return err
	}
	for _, task := range tasks {
		if value(task.Data.CapacityProviderName) == provider {
			return failure("ResourceInUseException", "The capacity provider is in use by an active task.")
		}
	}
	services, err := tx.Services(ServiceQuery{ClusterKey: key, IncludeInactive: true})
	if err != nil {
		return err
	}
	for _, service := range services {
		if status := value(service.Data.Status); status != "ACTIVE" && status != "DRAINING" {
			continue
		}
		if strategyUsesCapacityProvider(service.Data.CapacityProviderStrategy, provider) {
			return failure("ResourceInUseException", "The capacity provider is in use by a service strategy.")
		}
		for _, deployment := range service.Deployments {
			if value(deployment.Data.Status) != "INACTIVE" && strategyUsesCapacityProvider(deployment.Input.CapacityProviderStrategy, provider) {
				return failure("ResourceInUseException", "The capacity provider is in use by a service deployment.")
			}
		}
	}
	return nil
}

func strategyUsesCapacityProvider(strategy api.CapacityProviderStrategy, provider string) bool {
	for _, item := range strategy {
		if value(item.CapacityProvider) == provider {
			return true
		}
	}
	return false
}
