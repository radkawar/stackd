package eks

import (
	"context"
	"errors"
	"fmt"
	"slices"

	native "stackd/compute/eks"
	"stackd/compute/network"
	"stackd/internal/awsctx"
)

// podRouteObserver is optional: a runtime without current worker observations
// cannot authorize pod routing for a VPC containing EKS clusters.
type podRouteObserver interface {
	ObservePodRoutes(context.Context, native.Specification) ([]network.PodRoute, error)
}

// PodRoutes returns detached, current routing authority for exactly one VPC.
// Runtime observations never execute inside the repository transaction domain.
// Nothing is cached: cluster replacement, deletion and movement revoke the next
// observation even when a cluster name or a pod CIDR is reused.
func (s *Service) PodRoutes(ctx context.Context, partition, account, region, vpcID string) ([]network.PodRoute, error) {
	scope := Scope{Partition: partition, AccountID: account, Region: region}
	metadata := awsctx.FromContext(ctx)
	if partition == "" || account == "" || region == "" || vpcID == "" || metadata.Partition != partition || metadata.AccountID != account || metadata.Region != region {
		return nil, errors.New("eks: pod route request and resource scopes differ")
	}
	clusters, err := s.podRouteClusters(ctx, scope, vpcID)
	if err != nil {
		return nil, err
	}
	if len(clusters) == 0 {
		return nil, nil
	}
	observer, ok := s.runtime.(podRouteObserver)
	if !ok {
		return nil, errors.New("eks: current native pod route observer is unavailable")
	}
	var routes []network.PodRoute
	for _, cluster := range clusters {
		if cluster.ID == "" || (cluster.Status != "ACTIVE" && cluster.Status != "UPDATING") {
			return nil, errors.New("eks: cluster has no active pod routing authority")
		}
		observed, err := observer.ObservePodRoutes(ctx, native.Specification{ID: cluster.ID, Version: cluster.KubernetesVersion, Region: region})
		if err != nil {
			return nil, fmt.Errorf("eks: observing current cluster pod routes: %w", err)
		}
		for _, route := range observed {
			if route.ClusterID != cluster.ID || route.OwnerToken == "" || route.NodeName == "" || route.NodeUID == "" || route.ResourceVersion == "" || route.ContainerID == "" || route.NetworkID == "" ||
				!route.Prefix.IsValid() || !route.Prefix.Addr().Is4() || !route.Prefix.Addr().IsGlobalUnicast() || route.Prefix != route.Prefix.Masked() || route.Prefix.Bits() == 0 ||
				!route.WorkerIP.Is4() || !route.WorkerIP.IsGlobalUnicast() || route.Prefix.Contains(route.WorkerIP) {
				return nil, errors.New("eks: native pod route has foreign or incomplete worker authority")
			}
			routes = append(routes, route)
		}
	}
	slices.SortFunc(routes, func(a, b network.PodRoute) int {
		if order := a.Prefix.Addr().Compare(b.Prefix.Addr()); order != 0 {
			return order
		}
		return a.Prefix.Bits() - b.Prefix.Bits()
	})
	for i := 1; i < len(routes); i++ {
		if routes[i-1].Prefix.Overlaps(routes[i].Prefix) {
			return nil, errors.New("eks: overlapping pod routes in VPC")
		}
	}
	current, err := s.podRouteClusters(ctx, scope, vpcID)
	if err != nil {
		return nil, err
	}
	if len(current) != len(clusters) {
		return nil, errors.New("eks: cluster routing authority changed during observation")
	}
	for i, cluster := range clusters {
		now := current[i]
		if now.Key != cluster.Key || now.ID != cluster.ID || now.VPCID != cluster.VPCID || now.Status != cluster.Status || now.Generation != cluster.Generation {
			return nil, errors.New("eks: cluster routing authority changed during observation")
		}
	}
	return routes, nil
}

func (s *Service) podRouteClusters(ctx context.Context, scope Scope, vpcID string) ([]Cluster, error) {
	var selected []Cluster
	err := s.repository.View(ctx, func(reader Reader) error {
		clusters, err := reader.Clusters(scope)
		if err != nil {
			return err
		}
		for _, cluster := range clusters {
			if cluster.VPCID != vpcID {
				continue
			}
			if cluster.Key.Scope != scope {
				return errors.New("eks: cluster pod route scope differs from request")
			}
			for _, previous := range selected {
				if previous.ID == cluster.ID || previous.Key == cluster.Key {
					return errors.New("eks: ambiguous cluster pod route identity")
				}
			}
			selected = append(selected, cluster)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	slices.SortFunc(selected, func(a, b Cluster) int { return compareKey(a.Key, b.Key) })
	return selected, nil
}
