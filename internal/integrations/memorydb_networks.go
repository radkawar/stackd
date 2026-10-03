package integrations

import (
	"context"
	"errors"
	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/ec2"
	"stackd/internal/awscatalog"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/services/memorydb"
)

// MemoryDBNetworks resolves actual scoped EC2 subnet records using the current
// caller. It does not attach a local Valkey listener to an emulated VPC.
type MemoryDBNetworks struct {
	EC2 interface {
		ExecuteCommand(context.Context, awsapi.DecodedRequest) (any, *awswire.Error)
	}
}

func (a MemoryDBNetworks) ResolveSubnets(ctx context.Context, resource string, ids []string) ([]memorydb.Subnet, error) {
	parsed, e := arn.Parse(resource)
	m := awsctx.FromContext(ctx)
	if e != nil || parsed.Service != "memorydb" || parsed.Partition != m.Partition || parsed.AccountID != m.AccountID || parsed.Region != m.Region {
		return nil, errors.New("invalid MemoryDB subnet group scope")
	}
	input := &api.DescribeSubnetsRequest{SubnetIds: make(api.SubnetIdStringList, len(ids))}
	for i, id := range ids {
		input.SubnetIds[i] = api.SubnetId(id)
	}
	model, _ := awscatalog.LookupService("ec2")
	operation, _ := model.Operation("DescribeSubnets")
	out, rejected := a.EC2.ExecuteCommand(ctx, awsapi.DecodedRequest{Operation: operation, Protocol: model.Protocol, Input: input})
	if rejected != nil {
		return nil, rejected
	}
	result, ok := out.(*api.DescribeSubnetsResult)
	if !ok {
		return nil, errors.New("invalid EC2 subnet response")
	}
	found := make([]memorydb.Subnet, 0, len(result.Subnets))
	for _, subnet := range result.Subnets {
		if subnet.SubnetId == nil || subnet.VpcId == nil || subnet.AvailabilityZone == nil {
			return nil, errors.New("incomplete EC2 subnet")
		}
		found = append(found, memorydb.Subnet{ID: string(*subnet.SubnetId), VPCID: string(*subnet.VpcId), AvailabilityZone: string(*subnet.AvailabilityZone)})
	}
	return found, nil
}
