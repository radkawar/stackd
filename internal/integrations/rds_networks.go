package integrations

import (
	"context"
	"errors"

	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/ec2"
	"stackd/internal/awscatalog"
	"stackd/internal/awswire"
	"stackd/internal/services/rds"
)

// RDSNetworks reads scoped EC2-owned networking through the trusted RDS role.
// It does not imply that a native engine endpoint implements VPC packet policy.
type RDSNetworks struct {
	Roles *RDSRoles
	EC2   interface {
		ExecuteCommand(context.Context, awsapi.DecodedRequest) (any, *awswire.Error)
	}
}

func (a RDSNetworks) command(ctx context.Context, resource, action string, input any) (any, error) {
	ctx, err := a.Roles.context(ctx, resource, true)
	if err != nil {
		return nil, err
	}
	model, _ := awscatalog.LookupService("ec2")
	operation, _ := model.Operation(action)
	out, rejected := a.EC2.ExecuteCommand(ctx, awsapi.DecodedRequest{Operation: operation, Protocol: model.Protocol, Input: input})
	if rejected != nil {
		return nil, rejected
	}
	return out, nil
}

func (a RDSNetworks) ResolveSubnets(ctx context.Context, resource string, ids []string) ([]rds.Subnet, error) {
	input := &api.DescribeSubnetsRequest{SubnetIds: make(api.SubnetIdStringList, len(ids))}
	for i, id := range ids {
		input.SubnetIds[i] = api.SubnetId(id)
	}
	out, err := a.command(ctx, resource, "DescribeSubnets", input)
	if err != nil {
		return nil, err
	}
	result, ok := out.(*api.DescribeSubnetsResult)
	if !ok {
		return nil, errors.New("invalid EC2 subnet response")
	}
	found := make([]rds.Subnet, 0, len(result.Subnets))
	for _, subnet := range result.Subnets {
		if subnet.SubnetId == nil || subnet.VpcId == nil || subnet.AvailabilityZone == nil {
			return nil, errors.New("incomplete EC2 subnet")
		}
		found = append(found, rds.Subnet{ID: string(*subnet.SubnetId), VPCID: string(*subnet.VpcId), AvailabilityZone: string(*subnet.AvailabilityZone)})
	}
	return found, nil
}

func (a RDSNetworks) ValidateSecurityGroups(ctx context.Context, resource, vpc string, ids []string) error {
	input := &api.DescribeSecurityGroupsRequest{GroupIds: make(api.GroupIdStringList, len(ids))}
	for i, id := range ids {
		input.GroupIds[i] = api.SecurityGroupId(id)
	}
	out, err := a.command(ctx, resource, "DescribeSecurityGroups", input)
	if err != nil {
		return err
	}
	result, ok := out.(*api.DescribeSecurityGroupsResult)
	if !ok {
		return errors.New("invalid EC2 security group response")
	}
	for _, group := range result.SecurityGroups {
		if group.VpcId == nil || string(*group.VpcId) != vpc {
			return &awswire.Error{Code: "InvalidParameterCombination", Message: "The database subnets and security groups must belong to the same VPC.", StatusCode: 400}
		}
	}
	return nil
}
