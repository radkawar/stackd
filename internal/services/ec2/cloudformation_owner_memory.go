package ec2

import (
	"strings"

	"stackd/storage/memory"
)

// Memory mirrors SQLite: ordinary Put commands never change a row's private
// CloudFormation claim; only native admission sets it, and deletion clears it.
type claimedRecord[T any] interface {
	*T
	cloudFormationOwner() *CloudFormationOwner
}

func (v *VPCRecord) cloudFormationOwner() *CloudFormationOwner    { return &v.CloudFormationOwner }
func (v *SubnetRecord) cloudFormationOwner() *CloudFormationOwner { return &v.CloudFormationOwner }
func (v *SecurityGroupRecord) cloudFormationOwner() *CloudFormationOwner {
	return &v.CloudFormationOwner
}
func (v *SecurityGroupRuleRecord) cloudFormationOwner() *CloudFormationOwner {
	return &v.CloudFormationOwner
}
func (v *RouteTableRecord) cloudFormationOwner() *CloudFormationOwner { return &v.CloudFormationOwner }
func (v *InternetGatewayRecord) cloudFormationOwner() *CloudFormationOwner {
	return &v.CloudFormationOwner
}
func (v *NatGatewayRecord) cloudFormationOwner() *CloudFormationOwner  { return &v.CloudFormationOwner }
func (v *VPCEndpointRecord) cloudFormationOwner() *CloudFormationOwner { return &v.CloudFormationOwner }
func (v *NetworkInterfaceRecord) cloudFormationOwner() *CloudFormationOwner {
	return &v.CloudFormationOwner
}
func (v *NetworkACLRecord) cloudFormationOwner() *CloudFormationOwner  { return &v.CloudFormationOwner }
func (v *DHCPOptionsRecord) cloudFormationOwner() *CloudFormationOwner { return &v.CloudFormationOwner }
func (v *PublicAddressRecord) cloudFormationOwner() *CloudFormationOwner {
	return &v.CloudFormationOwner
}
func (v *InstanceRecord) cloudFormationOwner() *CloudFormationOwner { return &v.CloudFormationOwner }
func (v *LaunchTemplateRecord) cloudFormationOwner() *CloudFormationOwner {
	return &v.CloudFormationOwner
}
func (v *KeyPairRecord) cloudFormationOwner() *CloudFormationOwner { return &v.CloudFormationOwner }

func putClaimed[T any, P claimedRecord[T]](tx *memory.Transaction, table map[ResourceKey]T, k ResourceKey, v T, clone func(T) T) error {
	if err := tx.Check(true); err != nil {
		return err
	}
	var owner CloudFormationOwner
	if existing, ok := table[k]; ok {
		owner = *P(&existing).cloudFormationOwner()
	}
	*P(&v).cloudFormationOwner() = owner
	table[k] = clone(v)
	return nil
}

func setClaim[T any, P claimedRecord[T]](tx *memory.Transaction, table map[ResourceKey]T, k ResourceKey, owner CloudFormationOwner) error {
	if err := tx.Check(true); err != nil {
		return err
	}
	existing, ok := table[k]
	if !ok {
		return ErrNotFound
	}
	*P(&existing).cloudFormationOwner() = owner
	table[k] = existing
	return nil
}

func (r memoryReader) NetworkResourceOwner(k ResourceKey) (CloudFormationOwner, error) {
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
		return CloudFormationOwner{}, ErrNotFound
	}
}

func (w memoryWriter) PutNetworkResourceOwner(k ResourceKey, owner CloudFormationOwner) error {
	switch {
	case strings.HasPrefix(k.ID, "i-"):
		return setClaim(w.tx, w.s.instances, k, owner)
	case strings.HasPrefix(k.ID, "lt-"):
		return setClaim(w.tx, w.s.launchTemplates, k, owner)
	case strings.HasPrefix(k.ID, "key-"):
		return setClaim(w.tx, w.s.keyPairs, k, owner)
	case strings.HasPrefix(k.ID, "vpc-"):
		return setClaim(w.tx, w.s.vpcs, k, owner)
	case strings.HasPrefix(k.ID, "subnet-"):
		return setClaim(w.tx, w.s.subnets, k, owner)
	case strings.HasPrefix(k.ID, "sg-"):
		return setClaim(w.tx, w.s.groups, k, owner)
	case strings.HasPrefix(k.ID, "sgr-"):
		return setClaim(w.tx, w.s.rules, k, owner)
	case strings.HasPrefix(k.ID, "rtb-"):
		return setClaim(w.tx, w.s.routes, k, owner)
	case strings.HasPrefix(k.ID, "igw-"):
		return setClaim(w.tx, w.s.gateways, k, owner)
	case strings.HasPrefix(k.ID, "nat-"):
		return setClaim(w.tx, w.s.natGateways, k, owner)
	case strings.HasPrefix(k.ID, "vpce-"):
		return setClaim(w.tx, w.s.vpcEndpoints, k, owner)
	case strings.HasPrefix(k.ID, "eni-"):
		return setClaim(w.tx, w.s.networkInterfaces, k, owner)
	case strings.HasPrefix(k.ID, "acl-"):
		return setClaim(w.tx, w.s.acls, k, owner)
	case strings.HasPrefix(k.ID, "dopt-"):
		return setClaim(w.tx, w.s.dhcp, k, owner)
	case strings.HasPrefix(k.ID, "eipalloc-"):
		return setClaim(w.tx, w.s.publicAddresses, k, owner)
	default:
		return ErrNotFound
	}
}
