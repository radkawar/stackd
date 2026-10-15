package kafka

import (
	"context"
	"errors"
	"stackd/compute/network"
	"time"
)

// BrokerNetworkIdentity fences EC2 reservations to one immutable native broker.
// BrokerID is one-based and remains stable for the cluster's lifetime.
type BrokerNetworkIdentity struct {
	ClusterARN, Incarnation string
	BrokerID                int
}
type BrokerNetworkRequest struct {
	Identity                  BrokerNetworkIdentity
	SubnetIDs, SecurityGroups []string
}
type BrokerNetwork struct {
	InterfaceID, SubnetID, AvailabilityZone string
	Network                                 network.Specification
}

// NetworkControl delegates allocation and current packet policy to EC2. Native
// attachment effects run outside the shared resource transaction.
type NetworkControl interface {
	AllocateBrokerNetwork(context.Context, BrokerNetworkRequest) (BrokerNetwork, error)
	ObserveBrokerNetwork(context.Context, BrokerNetworkIdentity, string) (BrokerNetwork, error)
	ReleaseBrokerNetwork(context.Context, BrokerNetworkIdentity, string) error
}

type ServiceLinkedRoles interface {
	EnsureServiceLinkedRole(context.Context, string) error
}

// WithKafkaRoleUsage holds the resource snapshot through the IAM deletion
// decision. A pending native deletion still retains its service-linked role.
func (s *Service) WithKafkaRoleUsage(ctx context.Context, partition, account string, fn func(context.Context, []string) error) error {
	return s.repository.Update(ctx, func(tx Transaction) error {
		rows, err := tx.AllClusters()
		if err != nil {
			return err
		}
		var resources []string
		for _, cluster := range rows {
			if cluster.Partition == partition && cluster.AccountID == account && (len(cluster.ClientSubnets) > 0 || cluster.DefaultMetrics) {
				resources = append(resources, cluster.ARN)
			}
		}
		return fn(tx.Context(), resources)
	})
}

func (s *Service) networkSpecification(ctx context.Context, cluster ClusterRecord, spec Specification) (Specification, error) {
	if len(cluster.ClientSubnets) == 0 {
		return spec, nil
	}
	if s.networks == nil || len(cluster.BrokerNetworks) != int(cluster.Brokers) {
		return spec, errors.New("EC2 broker network ownership is unavailable or incomplete")
	}
	spec.Networks = make([]BrokerNetwork, cluster.Brokers)
	for _, retained := range cluster.BrokerNetworks {
		if retained.BrokerID < 1 || retained.BrokerID > int(cluster.Brokers) {
			return spec, errors.New("invalid retained broker identity")
		}
		current, err := s.networks.ObserveBrokerNetwork(ctx, BrokerNetworkIdentity{ClusterARN: cluster.ARN, Incarnation: cluster.Incarnation, BrokerID: retained.BrokerID}, retained.InterfaceID)
		if err != nil {
			return spec, err
		}
		if current.InterfaceID != retained.InterfaceID || current.SubnetID != retained.SubnetID || current.AvailabilityZone != retained.AvailabilityZone || current.Network.NetworkID != retained.NetworkID || !current.Network.Address.Is4() {
			return spec, errors.New("EC2 broker network identity changed")
		}
		spec.Networks[retained.BrokerID-1] = current
	}
	spec.RefreshNetwork = func(ctx context.Context, index int) (BrokerNetwork, error) {
		if index < 0 || index >= len(cluster.BrokerNetworks) {
			return BrokerNetwork{}, errors.New("invalid broker network index")
		}
		retained := cluster.BrokerNetworks[index]
		current, err := s.networks.ObserveBrokerNetwork(ctx, BrokerNetworkIdentity{ClusterARN: cluster.ARN, Incarnation: cluster.Incarnation, BrokerID: retained.BrokerID}, retained.InterfaceID)
		if err != nil {
			return current, err
		}
		if current.InterfaceID != retained.InterfaceID || current.SubnetID != retained.SubnetID || current.AvailabilityZone != retained.AvailabilityZone || current.Network.NetworkID != retained.NetworkID {
			return current, errors.New("EC2 broker network identity changed during refresh")
		}
		return current, nil
	}
	return spec, nil
}

func (s *Service) releaseBrokerNetworks(ctx context.Context, cluster ClusterRecord) error {
	if len(cluster.BrokerNetworks) == 0 {
		return nil
	}
	if s.networks == nil {
		return errors.New("EC2 broker network owner is unavailable")
	}
	for _, retained := range cluster.BrokerNetworks {
		if err := s.networks.ReleaseBrokerNetwork(ctx, BrokerNetworkIdentity{ClusterARN: cluster.ARN, Incarnation: cluster.Incarnation, BrokerID: retained.BrokerID}, retained.InterfaceID); err != nil {
			return err
		}
	}
	return nil
}

// quarantineManaged runs after the prerequisite read has left its transaction.
// Losing EC2 observation must not leave the previous permissive policy serving.
func (s *Service) quarantineManaged(ctx context.Context, cluster ClusterRecord, cause error) error {
	if len(cluster.ClientSubnets) == 0 {
		return cause
	}
	runtime, ok := s.runtime.(QuarantineRuntime)
	if !ok {
		return errors.Join(cause, errors.New("managed Kafka quarantine runtime is unavailable"))
	}
	cleanup, cancel := context.WithTimeout(context.WithoutCancel(runtimeContext(ctx, cluster)), 30*time.Second)
	defer cancel()
	return errors.Join(cause, runtime.Quarantine(cleanup, baseSpecification(cluster)))
}
