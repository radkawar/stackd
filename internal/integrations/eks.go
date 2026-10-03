package integrations

import (
	"context"
	"errors"
	"time"

	"stackd/internal/authorization"
	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/ec2"
	"stackd/internal/awscatalog"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/identity"
)

// EKSPrincipals binds access entries to the IAM owner's immutable identity.
type EKSPrincipals struct {
	IAM interface {
		ResolvePrincipal(context.Context, string) (authorization.Principal, error)
	}
}

func (a EKSPrincipals) ResolvePrincipal(ctx context.Context, arn string) (string, error) {
	if a.IAM == nil {
		return "", errors.New("IAM principal owner unavailable")
	}
	p, e := a.IAM.ResolvePrincipal(ctx, arn)
	if e != nil {
		return "", e
	}
	return p.ID, nil
}

// EKSNetworks validates native EC2 ownership through the cluster's current trusted
// execution role. The Kubernetes adapter does not claim these subnets as its CNI.
type EKSNetworks struct {
	Roles ServiceRoles
	EC2   interface {
		ExecuteCommand(context.Context, awsapi.DecodedRequest) (any, *awswire.Error)
	}
}

func (a EKSNetworks) ValidateClusterNetwork(ctx context.Context, role, resource string, subnets, groups []string) (string, error) {
	credential, rejected := a.Roles.assume(ctx, awsctx.ServicePrincipal{Name: "eks.amazonaws.com", SourceARN: resource, Type: "AWSService"}, role, identity.RoleSessionSpec{SessionName: "EKSCluster", Duration: time.Hour}, "")
	if rejected != nil {
		return "", rejected
	}
	ctx, rejected = serviceRoleRequestContext(ctx, credential, awsctx.FromContext(ctx).Region, "eks.amazonaws.com")
	if rejected != nil {
		return "", rejected
	}
	if a.EC2 == nil {
		return "", errors.New("EC2 network owner unavailable")
	}
	model, _ := awscatalog.LookupService("ec2")
	op, _ := model.Operation("DescribeSubnets")
	input := &api.DescribeSubnetsRequest{SubnetIds: make(api.SubnetIdStringList, len(subnets))}
	for i, id := range subnets {
		input.SubnetIds[i] = api.SubnetId(id)
	}
	out, rejected := a.EC2.ExecuteCommand(ctx, awsapi.DecodedRequest{Operation: op, Protocol: model.Protocol, Input: input})
	if rejected != nil {
		return "", rejected
	}
	result, ok := out.(*api.DescribeSubnetsResult)
	if !ok {
		return "", errors.New("invalid EC2 subnet response")
	}
	vpc := ""
	zones := map[string]bool{}
	seen := map[string]bool{}
	for _, subnet := range result.Subnets {
		if subnet.SubnetId == nil || subnet.VpcId == nil || subnet.AvailabilityZone == nil {
			return "", errors.New("incomplete EC2 subnet")
		}
		seen[string(*subnet.SubnetId)] = true
		if vpc != "" && vpc != string(*subnet.VpcId) {
			return "", eksNetworkInvalid("Subnets must belong to the same VPC.")
		}
		vpc = string(*subnet.VpcId)
		zones[string(*subnet.AvailabilityZone)] = true
	}
	if len(zones) < 2 || len(seen) != len(subnets) {
		return "", eksNetworkInvalid("Subnets must span at least two Availability Zones and cannot be duplicated.")
	}
	if len(groups) > 0 {
		op, _ = model.Operation("DescribeSecurityGroups")
		input := &api.DescribeSecurityGroupsRequest{GroupIds: make(api.GroupIdStringList, len(groups))}
		for i, id := range groups {
			input.GroupIds[i] = api.SecurityGroupId(id)
		}
		out, rejected = a.EC2.ExecuteCommand(ctx, awsapi.DecodedRequest{Operation: op, Protocol: model.Protocol, Input: input})
		if rejected != nil {
			return "", rejected
		}
		result, ok := out.(*api.DescribeSecurityGroupsResult)
		if !ok {
			return "", errors.New("invalid EC2 security group response")
		}
		for _, group := range result.SecurityGroups {
			if group.VpcId == nil || string(*group.VpcId) != vpc {
				return "", eksNetworkInvalid("Security groups must belong to the cluster VPC.")
			}
		}
	}
	return vpc, nil
}
func eksNetworkInvalid(message string) *awswire.Error {
	return &awswire.Error{Code: "InvalidParameterException", Message: message, StatusCode: 400}
}
