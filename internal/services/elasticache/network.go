package elasticache

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"stackd/compute/network"
	engine "stackd/engine/valkey"
	api "stackd/internal/awsapi/elasticache"
	"stackd/internal/awsctx"
	"strings"
	"time"
)

// CacheNodeNetworkIdentity fences an EC2 reservation to one cache incarnation.
// NodeIndex is one-based and stable: shard*(replicas+1)+replica+1.
type CacheNodeNetworkIdentity struct {
	ClusterARN, Incarnation string
	NodeIndex               int
}
type CacheNodeNetworkRequest struct {
	Identity                  CacheNodeNetworkIdentity
	SubnetIDs, SecurityGroups []string
}
type CacheNodeNetwork struct {
	InterfaceID, SubnetID, AvailabilityZone string
	Network                                 network.Specification
}

// CacheNodePlacement retains immutable reservation identity, never packet policy.
// Current policy and DHCP authority are reobserved outside resource transactions.
type CacheNodePlacement struct {
	NodeIndex                                          int
	InterfaceID, SubnetID, AvailabilityZone, NetworkID string
	Address, Gateway                                   netip.Addr
	Pool                                               netip.Prefix
	MAC                                                string
}

type ServiceLinkedRoles interface {
	EnsureServiceLinkedRole(context.Context, string) error
}

// WithElastiCacheRoleUsage holds the resource snapshot through IAM's deletion
// decision. Creating, failed and deleting placement retains its source role.
func (s *Service) WithElastiCacheRoleUsage(ctx context.Context, partition, account string, fn func(context.Context, []string) error) error {
	return s.repository.Update(ctx, func(tx Transaction) error {
		rows, err := tx.AllClusters()
		if err != nil {
			return err
		}
		var resources []string
		for _, cluster := range rows {
			if cluster.Key.Partition == partition && cluster.Key.AccountID == account && (cluster.SubnetGroup != "" || len(cluster.NodePlacements) != 0) {
				resources = append(resources, cluster.Key.ARN())
			}
		}
		return fn(tx.Context(), resources)
	})
}

type quarantineRuntime interface {
	Quarantine(context.Context, engine.Specification) error
}

func (s *Service) preparePlacement(ctx context.Context, tx Transaction, v *Cluster) error {
	if v.SubnetGroup == "" {
		if len(v.SecurityGroups) != 0 || v.ClientPort != 0 {
			return unsupported("Security groups and configured ports require explicit CacheSubnetGroupName placement.")
		}
		return nil
	}
	if s.networks == nil || s.roles == nil {
		return unsupported("Managed cache placement requires EC2 and service-linked-role owners.")
	}
	if _, ok := s.runtime.(quarantineRuntime); !ok {
		return unsupported("Managed cache placement requires a fail-closed native runtime.")
	}
	if count := int(v.Shards) * (int(v.Replicas) + 1); count < 1 || count > 32 {
		return unsupported("Managed native cache placement supports at most32 nodes.")
	}
	if v.ClientPort == 0 {
		v.ClientPort = 6379
	}
	if v.ClientPort != 6379 {
		return unsupported("Managed native cache placement supports configured client port6379.")
	}
	if len(v.SecurityGroups) == 0 {
		return unsupported("Managed native cache placement requires explicit security group IDs.")
	}
	for index, group := range v.SecurityGroups {
		if group == "" || slices.Contains(v.SecurityGroups[:index], group) {
			return failure("InvalidParameterValue", "Security group IDs must be nonempty and unique.")
		}
	}
	action := "CreateCacheCluster"
	if v.Key.Kind == "replicationgroup" {
		action = "CreateReplicationGroup"
	}
	group, err := s.loadSubnetGroup(ctx, tx, action, v.SubnetGroup)
	if err != nil {
		return err
	}
	if len(group.Subnets) == 0 || group.VPCID == "" {
		return failure("InvalidSubnet", "The cache subnet group has no authoritative EC2 placement.")
	}
	v.ClientSubnets = make([]string, len(group.Subnets))
	for index, subnet := range group.Subnets {
		v.ClientSubnets[index] = subnet.ID
	}
	return s.roles.EnsureServiceLinkedRole(ctx, "elasticache.amazonaws.com")
}

func cacheNetworkIdentity(v Cluster, index int) CacheNodeNetworkIdentity {
	return CacheNodeNetworkIdentity{ClusterARN: v.Key.ARN(), Incarnation: v.RuntimeID, NodeIndex: index}
}

func managedRuntimeContext(ctx context.Context, v Cluster) context.Context {
	ctx = runtimeContext(ctx, v.Key)
	if v.SubnetGroup == "" {
		return ctx
	}
	metadata := awsctx.FromContext(ctx)
	metadata.IssuerARN = "arn:" + v.Key.Partition + ":iam::" + v.Key.AccountID + ":role/aws-service-role/elasticache.amazonaws.com/AWSServiceRoleForElastiCache"
	return awsctx.WithMetadata(ctx, metadata)
}

func retainedPlacement(index int, current CacheNodeNetwork) (CacheNodePlacement, error) {
	n := current.Network
	mac, macErr := net.ParseMAC(n.MAC)
	if current.InterfaceID == "" || current.SubnetID == "" || current.AvailabilityZone == "" ||
		n.NetworkID == "" || !n.Address.Is4() || n.Address.IsLoopback() || n.Address.IsUnspecified() ||
		!n.Gateway.Is4() || !n.Pool.IsValid() || !n.Pool.Addr().Is4() || n.Pool != n.Pool.Masked() ||
		!n.Pool.Contains(n.Address) || !n.Pool.Contains(n.Gateway) || n.Address == n.Gateway ||
		macErr != nil || len(mac) != 6 || mac[0]&1 != 0 {
		return CacheNodePlacement{}, errors.New("EC2 returned incomplete native cache placement")
	}
	return CacheNodePlacement{NodeIndex: index, InterfaceID: current.InterfaceID,
		SubnetID: current.SubnetID, AvailabilityZone: current.AvailabilityZone, NetworkID: n.NetworkID,
		Address: n.Address, Gateway: n.Gateway, Pool: n.Pool, MAC: strings.ToLower(n.MAC)}, nil
}

// allocateCacheNetworks checkpoints each successful effect separately, outside
// cache transactions. A failed later allocation never discards earlier ownership.
func (s *Service) allocateCacheNetworks(ctx context.Context, v Cluster) (Cluster, error) {
	if v.SubnetGroup == "" {
		return v, nil
	}
	if s.networks == nil {
		return v, errors.New("native cache EC2 owner is unavailable")
	}
	count := int(v.Shards * (v.Replicas + 1))
	for index := 1; index <= count; index++ {
		present := false
		for _, placement := range v.NodePlacements {
			if placement.NodeIndex == index {
				present = true
				break
			}
		}
		if present {
			continue
		}
		identity := cacheNetworkIdentity(v, index)
		current, err := s.networks.AllocateCacheNodeNetwork(ctx, CacheNodeNetworkRequest{
			Identity: identity, SubnetIDs: v.ClientSubnets, SecurityGroups: v.SecurityGroups,
		})
		if err != nil {
			return v, err
		}
		placement, err := retainedPlacement(index, current)
		if err == nil && !slices.Contains(v.ClientSubnets, placement.SubnetID) {
			err = errors.New("EC2 allocated a cache node outside its requested subnets")
		}
		if err == nil {
			err = s.repository.Update(ctx, func(tx Transaction) error {
				actual, err := tx.Cluster(v.Key)
				if err != nil {
					return err
				}
				if actual.RuntimeID != v.RuntimeID || actual.Version != v.Version || actual.Operation != v.Operation {
					return errors.New("native cache allocation lost its incarnation/version fence")
				}
				for _, prior := range actual.NodePlacements {
					if prior.NodeIndex == index {
						if prior != placement {
							return errors.New("native cache reservation changed during allocation")
						}
						v = actual
						return nil
					}
					if prior.InterfaceID == placement.InterfaceID || prior.Address == placement.Address || prior.MAC == placement.MAC {
						return errors.New("EC2 reused one native cache reservation for multiple nodes")
					}
				}
				actual.NodePlacements = append(actual.NodePlacements, placement)
				slices.SortFunc(actual.NodePlacements, func(a, b CacheNodePlacement) int { return a.NodeIndex - b.NodeIndex })
				if err = tx.PutCluster(actual); err != nil {
					return err
				}
				v = actual
				return nil
			})
		}
		if err != nil {
			cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
			cleanupErr := s.networks.ReleaseCacheNodeNetwork(cleanup, identity, current.InterfaceID)
			cancel()
			return v, errors.Join(err, cleanupErr)
		}
	}
	return v, nil
}

func (s *Service) networkSpecification(ctx context.Context, v Cluster, spec engine.Specification) (engine.Specification, error) {
	if v.SubnetGroup == "" {
		return spec, nil
	}
	count := int(v.Shards * (v.Replicas + 1))
	if s.networks == nil || len(v.NodePlacements) != count {
		return spec, errors.New("native cache EC2 ownership is unavailable or incomplete")
	}
	spec.ClusterARN = v.Key.ARN()
	spec.Networks = make([]engine.NodeNetwork, count)
	observe := func(ctx context.Context, index int) (engine.NodeNetwork, error) {
		if index < 0 || index >= count {
			return engine.NodeNetwork{}, errors.New("invalid native cache node index")
		}
		retained := v.NodePlacements[index]
		if retained.NodeIndex != index+1 {
			return engine.NodeNetwork{}, errors.New("invalid retained native cache node order")
		}
		current, err := s.networks.ObserveCacheNodeNetwork(ctx, cacheNetworkIdentity(v, index+1), retained.InterfaceID)
		if err != nil {
			return engine.NodeNetwork{}, err
		}
		actual, err := retainedPlacement(index+1, current)
		if err != nil {
			return engine.NodeNetwork{}, err
		}
		if actual != retained {
			return engine.NodeNetwork{}, errors.New("EC2 cache reservation identity changed")
		}
		return engine.NodeNetwork{InterfaceID: current.InterfaceID, Network: current.Network}, nil
	}
	for index := range spec.Networks {
		current, err := observe(ctx, index)
		if err != nil {
			return spec, err
		}
		spec.Networks[index] = current
	}
	spec.RefreshNetwork = observe
	return spec, nil
}

func (s *Service) quarantineManaged(ctx context.Context, v Cluster, cause error) error {
	if v.SubnetGroup == "" {
		return cause
	}
	runtime, ok := s.runtime.(quarantineRuntime)
	if !ok {
		return errors.Join(cause, errors.New("native cache quarantine is unavailable"))
	}
	cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancel()
	spec := engine.Specification{ClusterARN: v.Key.ARN(), ID: v.RuntimeID,
		Shards: v.Shards, Replicas: v.Replicas, ClusterMode: v.ClusterMode, TLSEnabled: v.TLSEnabled}
	return errors.Join(cause, runtime.Quarantine(cleanup, spec))
}

func (s *Service) releaseCacheNetworks(ctx context.Context, v Cluster) error {
	if len(v.NodePlacements) == 0 {
		return nil
	}
	if s.networks == nil {
		return errors.New("native cache EC2 owner is unavailable for deletion")
	}
	for _, placement := range v.NodePlacements {
		if err := s.networks.ReleaseCacheNodeNetwork(ctx, cacheNetworkIdentity(v, placement.NodeIndex), placement.InterfaceID); err != nil {
			return err
		}
	}
	return nil
}

func validateManagedDeployment(v Cluster, deployment engine.Deployment) error {
	if v.SubnetGroup == "" {
		return nil
	}
	if len(deployment.Nodes) != len(v.NodePlacements) || len(v.NodePlacements) > 32 {
		return errors.New("native cache deployment differs from retained EC2 topology")
	}
	var seen [32]bool
	for _, node := range deployment.Nodes {
		index := int(node.Shard*(v.Replicas+1) + node.Replica)
		if node.Shard < 0 || node.Shard >= v.Shards || node.Replica < 0 || node.Replica > v.Replicas ||
			index < 0 || index >= len(v.NodePlacements) || seen[index] || node.ID == "" {
			return errors.New("native cache deployment has an invalid or repeated node identity")
		}
		seen[index] = true
		if node.Endpoint.Address != v.NodePlacements[index].Address.String() || node.Endpoint.Port != v.ClientPort {
			return fmt.Errorf("native cache node%d did not open its actual EC2 address/configured port", index+1)
		}
	}
	return nil
}

func securityGroupIDs(ids api.SecurityGroupIdsList) []string {
	if len(ids) == 0 {
		return nil
	}
	values := make([]string, len(ids))
	for index, id := range ids {
		values[index] = string(id)
	}
	return values
}
