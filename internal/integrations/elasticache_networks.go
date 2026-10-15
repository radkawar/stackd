package integrations

import (
	"context"
	"errors"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"stackd/internal/apievents"
	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/ec2"
	"stackd/internal/awscatalog"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/services/ec2"
	"stackd/internal/services/elasticache"
)

// ElastiCacheNetworks resolves customer subnets with the caller's current IAM
// authority and reserves native node networks with the actual ElastiCache role.
// EC2 owns placement, immutable reservation fences and current packet policy.
type ElastiCacheNetworks struct {
	EC2 interface {
		ExecuteCommand(context.Context, awsapi.DecodedRequest) (any, *awswire.Error)
		AllocateCacheNodeNetwork(context.Context, ec2.CacheNodeNetworkRequest) (ec2.CacheNodeNetwork, error)
		ObserveCacheNodeNetwork(context.Context, ec2.CacheNodeNetworkIdentity, string) (ec2.CacheNodeNetwork, error)
		ReleaseCacheNodeNetwork(context.Context, ec2.CacheNodeNetworkIdentity, string) error
	}
	Roles    ServiceRoles
	sessions serviceRoleSessions
}

var _ elasticache.NetworkControl = (*ElastiCacheNetworks)(nil)

func (a *ElastiCacheNetworks) ResolveSubnets(ctx context.Context, _ string, ids []string) ([]elasticache.Subnet, error) {
	if a.EC2 == nil {
		return nil, errors.New("native ElastiCache EC2 network owner is unavailable")
	}
	in := &api.DescribeSubnetsRequest{SubnetIds: make(api.SubnetIdStringList, len(ids))}
	for i, id := range ids {
		in.SubnetIds[i] = api.SubnetId(id)
	}
	model, _ := awscatalog.LookupService("ec2")
	op, _ := model.Operation("DescribeSubnets")
	out, rejected := a.EC2.ExecuteCommand(ctx, awsapi.DecodedRequest{Operation: op, Protocol: model.Protocol, Input: in})
	if rejected != nil {
		return nil, rejected
	}
	result, ok := out.(*api.DescribeSubnetsResult)
	if !ok {
		return nil, errors.New("invalid EC2 subnet response")
	}
	subnets := make([]elasticache.Subnet, 0, len(result.Subnets))
	for _, sub := range result.Subnets {
		if sub.SubnetId == nil || sub.VpcId == nil || sub.AvailabilityZone == nil {
			return nil, errors.New("incomplete EC2 subnet response")
		}
		subnets = append(subnets, elasticache.Subnet{ID: string(*sub.SubnetId), VPCID: string(*sub.VpcId), AvailabilityZone: string(*sub.AvailabilityZone)})
	}
	return subnets, nil
}

func (a *ElastiCacheNetworks) serviceContext(ctx context.Context, identity elasticache.CacheNodeNetworkIdentity) (context.Context, error) {
	if a.EC2 == nil {
		return nil, errors.New("native ElastiCache EC2 network owner is unavailable")
	}
	metadata := awsctx.FromContext(ctx)
	cluster, err := arn.Parse(identity.ClusterARN)
	if err != nil || !validElastiCacheOwner(cluster) || cluster.Partition != metadata.Partition || cluster.AccountID != metadata.AccountID || cluster.Region != metadata.Region || identity.Incarnation == "" || identity.NodeIndex < 1 {
		return nil, errors.New("native ElastiCache network owner and request scopes differ")
	}
	if parent := apievents.EventID(ctx); parent != "" {
		metadata.ParentEventID = parent
		ctx = awsctx.WithMetadata(ctx, metadata)
	}
	role := "arn:" + metadata.Partition + ":iam::" + metadata.AccountID + ":role/aws-service-role/" + elastiCacheServicePrincipal + "/" + elastiCacheServiceRole
	return a.sessions.context(ctx, a.Roles, awsctx.ServicePrincipal{Name: elastiCacheServicePrincipal, SourceARN: identity.ClusterARN, Type: "AWSService"}, role, "elasticache-eni-provisioning", "")
}

func (a *ElastiCacheNetworks) AllocateCacheNodeNetwork(ctx context.Context, request elasticache.CacheNodeNetworkRequest) (elasticache.CacheNodeNetwork, error) {
	service, err := a.serviceContext(ctx, request.Identity)
	if err != nil {
		return elasticache.CacheNodeNetwork{}, err
	}
	result, err := a.EC2.AllocateCacheNodeNetwork(service, ec2.CacheNodeNetworkRequest{
		Identity: ec2CacheNodeIdentity(request.Identity), SubnetIDs: request.SubnetIDs, SecurityGroups: request.SecurityGroups,
	})
	if err != nil {
		return elasticache.CacheNodeNetwork{}, err
	}
	return elastiCacheNodeNetwork(result), nil
}

func (a *ElastiCacheNetworks) ObserveCacheNodeNetwork(ctx context.Context, identity elasticache.CacheNodeNetworkIdentity, interfaceID string) (elasticache.CacheNodeNetwork, error) {
	service, err := a.serviceContext(ctx, identity)
	if err != nil {
		return elasticache.CacheNodeNetwork{}, err
	}
	result, err := a.EC2.ObserveCacheNodeNetwork(service, ec2CacheNodeIdentity(identity), interfaceID)
	if err != nil {
		return elasticache.CacheNodeNetwork{}, err
	}
	return elastiCacheNodeNetwork(result), nil
}

func (a *ElastiCacheNetworks) ReleaseCacheNodeNetwork(ctx context.Context, identity elasticache.CacheNodeNetworkIdentity, interfaceID string) error {
	service, err := a.serviceContext(ctx, identity)
	if err != nil {
		return err
	}
	return a.EC2.ReleaseCacheNodeNetwork(service, ec2CacheNodeIdentity(identity), interfaceID)
}

func ec2CacheNodeIdentity(identity elasticache.CacheNodeNetworkIdentity) ec2.CacheNodeNetworkIdentity {
	return ec2.CacheNodeNetworkIdentity{ClusterARN: identity.ClusterARN, Incarnation: identity.Incarnation, NodeIndex: identity.NodeIndex}
}

func elastiCacheNodeNetwork(result ec2.CacheNodeNetwork) elasticache.CacheNodeNetwork {
	return elasticache.CacheNodeNetwork{
		InterfaceID:      ecsNetworkString(result.Interface.NetworkInterfaceId),
		SubnetID:         ecsNetworkString(result.Interface.SubnetId),
		AvailabilityZone: ecsNetworkString(result.Interface.AvailabilityZone),
		Network:          result.Network,
	}
}

func validElastiCacheOwner(resource arn.ARN) bool {
	kind, name, found := strings.Cut(resource.Resource, ":")
	return resource.Service == "elasticache" && resource.Partition != "" && resource.AccountID != "" && resource.Region != "" &&
		found && (kind == "cluster" || kind == "replicationgroup") && name != "" && !strings.ContainsAny(name, ":/")
}
