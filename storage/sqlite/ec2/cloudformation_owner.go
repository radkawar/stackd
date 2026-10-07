package ec2

import (
	domain "stackd/storage/ec2"
	"stackd/storage/sqlite/ec2/internal/sqlcgen"
	"strings"
)

// cloudFormationOwner restores the private typed claim; empty columns are the
// unclaimed state of rows created before schema 390 or outside CloudFormation.
func cloudFormationOwner(resourceType, owner string) domain.CloudFormationOwner {
	return domain.CloudFormationOwner{ResourceType: resourceType, Owner: owner}
}

func (r reader) NetworkResourceOwner(k domain.ResourceKey) (domain.CloudFormationOwner, error) {
	switch {
	case strings.HasPrefix(k.ID, "i-"):
		v, err := r.Instance(k)
		return v.CloudFormationOwner, err
	case strings.HasPrefix(k.ID, "lt-"):
		v, err := r.LaunchTemplate(k)
		return v.CloudFormationOwner, err
	case strings.HasPrefix(k.ID, "key-"):
		v, err := r.KeyPair(k)
		return v.CloudFormationOwner, err
	case strings.HasPrefix(k.ID, "vpc-"):
		v, err := r.VPC(k)
		return v.CloudFormationOwner, err
	case strings.HasPrefix(k.ID, "subnet-"):
		v, err := r.Subnet(k)
		return v.CloudFormationOwner, err
	case strings.HasPrefix(k.ID, "sg-"):
		v, err := r.SecurityGroup(k)
		return v.CloudFormationOwner, err
	case strings.HasPrefix(k.ID, "sgr-"):
		v, err := r.SecurityGroupRule(k)
		return v.CloudFormationOwner, err
	case strings.HasPrefix(k.ID, "rtb-"):
		v, err := r.RouteTable(k)
		return v.CloudFormationOwner, err
	case strings.HasPrefix(k.ID, "igw-"):
		v, err := r.InternetGateway(k)
		return v.CloudFormationOwner, err
	case strings.HasPrefix(k.ID, "nat-"):
		v, err := r.NatGateway(k)
		return v.CloudFormationOwner, err
	case strings.HasPrefix(k.ID, "vpce-"):
		v, err := r.VPCEndpoint(k)
		return v.CloudFormationOwner, err
	case strings.HasPrefix(k.ID, "eni-"):
		v, err := r.NetworkInterface(k)
		return v.CloudFormationOwner, err
	case strings.HasPrefix(k.ID, "acl-"):
		v, err := r.NetworkACL(k)
		return v.CloudFormationOwner, err
	case strings.HasPrefix(k.ID, "dopt-"):
		v, err := r.DHCPOptions(k)
		return v.CloudFormationOwner, err
	case strings.HasPrefix(k.ID, "eipalloc-"):
		v, err := r.PublicAddress(k)
		return v.CloudFormationOwner, err
	default:
		return domain.CloudFormationOwner{}, domain.ErrNotFound
	}
}

func (w writer) PutNetworkResourceOwner(k domain.ResourceKey, owner domain.CloudFormationOwner) error {
	switch {
	case strings.HasPrefix(k.ID, "i-"):
		return deleted(w.q.SetInstanceCloudFormationOwner(w.ctx, sqlcgen.SetInstanceCloudFormationOwnerParams{Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID, CloudformationResourceType: owner.ResourceType, CloudformationOwner: owner.Owner}))
	case strings.HasPrefix(k.ID, "lt-"):
		return deleted(w.q.SetLaunchTemplateCloudFormationOwner(w.ctx, sqlcgen.SetLaunchTemplateCloudFormationOwnerParams{Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID, CloudformationResourceType: owner.ResourceType, CloudformationOwner: owner.Owner}))
	case strings.HasPrefix(k.ID, "key-"):
		return deleted(w.q.SetKeyPairCloudFormationOwner(w.ctx, sqlcgen.SetKeyPairCloudFormationOwnerParams{Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID, CloudformationResourceType: owner.ResourceType, CloudformationOwner: owner.Owner}))
	case strings.HasPrefix(k.ID, "vpc-"):
		return deleted(w.q.SetVpcCloudFormationOwner(w.ctx, sqlcgen.SetVpcCloudFormationOwnerParams{Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID, CloudformationResourceType: owner.ResourceType, CloudformationOwner: owner.Owner}))
	case strings.HasPrefix(k.ID, "subnet-"):
		return deleted(w.q.SetSubnetCloudFormationOwner(w.ctx, sqlcgen.SetSubnetCloudFormationOwnerParams{Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID, CloudformationResourceType: owner.ResourceType, CloudformationOwner: owner.Owner}))
	case strings.HasPrefix(k.ID, "sg-"):
		return deleted(w.q.SetSecurityGroupCloudFormationOwner(w.ctx, sqlcgen.SetSecurityGroupCloudFormationOwnerParams{Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID, CloudformationResourceType: owner.ResourceType, CloudformationOwner: owner.Owner}))
	case strings.HasPrefix(k.ID, "sgr-"):
		return deleted(w.q.SetSecurityGroupRuleCloudFormationOwner(w.ctx, sqlcgen.SetSecurityGroupRuleCloudFormationOwnerParams{Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID, CloudformationResourceType: owner.ResourceType, CloudformationOwner: owner.Owner}))
	case strings.HasPrefix(k.ID, "rtb-"):
		return deleted(w.q.SetRouteTableCloudFormationOwner(w.ctx, sqlcgen.SetRouteTableCloudFormationOwnerParams{Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID, CloudformationResourceType: owner.ResourceType, CloudformationOwner: owner.Owner}))
	case strings.HasPrefix(k.ID, "igw-"):
		return deleted(w.q.SetInternetGatewayCloudFormationOwner(w.ctx, sqlcgen.SetInternetGatewayCloudFormationOwnerParams{Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID, CloudformationResourceType: owner.ResourceType, CloudformationOwner: owner.Owner}))
	case strings.HasPrefix(k.ID, "nat-"):
		return deleted(w.q.SetNatGatewayCloudFormationOwner(w.ctx, sqlcgen.SetNatGatewayCloudFormationOwnerParams{Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID, CloudformationResourceType: owner.ResourceType, CloudformationOwner: owner.Owner}))
	case strings.HasPrefix(k.ID, "vpce-"):
		return deleted(w.q.SetVPCEndpointCloudFormationOwner(w.ctx, sqlcgen.SetVPCEndpointCloudFormationOwnerParams{Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID, CloudformationResourceType: owner.ResourceType, CloudformationOwner: owner.Owner}))
	case strings.HasPrefix(k.ID, "eni-"):
		return deleted(w.q.SetNetworkInterfaceCloudFormationOwner(w.ctx, sqlcgen.SetNetworkInterfaceCloudFormationOwnerParams{Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID, CloudformationResourceType: owner.ResourceType, CloudformationOwner: owner.Owner}))
	case strings.HasPrefix(k.ID, "acl-"):
		return deleted(w.q.SetNetworkAclCloudFormationOwner(w.ctx, sqlcgen.SetNetworkAclCloudFormationOwnerParams{Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID, CloudformationResourceType: owner.ResourceType, CloudformationOwner: owner.Owner}))
	case strings.HasPrefix(k.ID, "dopt-"):
		return deleted(w.q.SetDhcpOptionsCloudFormationOwner(w.ctx, sqlcgen.SetDhcpOptionsCloudFormationOwnerParams{Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID, CloudformationResourceType: owner.ResourceType, CloudformationOwner: owner.Owner}))
	case strings.HasPrefix(k.ID, "eipalloc-"):
		return deleted(w.q.SetPublicAddressCloudFormationOwner(w.ctx, sqlcgen.SetPublicAddressCloudFormationOwnerParams{Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID, CloudformationResourceType: owner.ResourceType, CloudformationOwner: owner.Owner}))
	default:
		return domain.ErrNotFound
	}
}
