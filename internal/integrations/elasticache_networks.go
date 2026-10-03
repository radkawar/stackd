package integrations

import (
	"context"
	"errors"
	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/ec2"
	"stackd/internal/awscatalog"
	"stackd/internal/awswire"
	"stackd/internal/services/elasticache"
)

// ElastiCacheNetworks resolves subnets through current EC2 authorization. It
// deliberately does not represent native endpoint routing or VPC enforcement.
type ElastiCacheNetworks struct {
	EC2 interface {
		ExecuteCommand(context.Context, awsapi.DecodedRequest) (any, *awswire.Error)
	}
}

func (a ElastiCacheNetworks) ResolveSubnets(ctx context.Context, _ string, ids []string) ([]elasticache.Subnet, error) {
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
