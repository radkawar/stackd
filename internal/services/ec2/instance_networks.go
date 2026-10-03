package ec2

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"strconv"
	"strings"

	api "stackd/internal/awsapi/ec2"
)

// privateDNSName is the EC2 IP-based private hostname. Its regional suffix is
// independent of the VPC's configurable DHCP search domain.
func privateDNSName(scope Scope, address string) string {
	if address == "" {
		return ""
	}
	domain := scope.Region + ".compute.internal"
	if scope.Region == "us-east-1" {
		domain = "ec2.internal"
	}
	return "ip-" + strings.ReplaceAll(address, ".", "-") + "." + domain
}

type instanceNetworkPlan struct {
	subnet   SubnetRecord
	groups   []SecurityGroupRecord
	spec     api.InstanceNetworkInterfaceSpecification
	existing *NetworkInterfaceRecord
}

func (s *Service) planInstanceNetwork(ctx context.Context, tx Reader, in *api.RunInstancesRequest, tags api.TagList) (instanceNetworkPlan, error) {
	var plan instanceNetworkPlan
	if len(in.NetworkInterfaces) > 0 && (in.SubnetId != nil || len(in.SecurityGroupIds) > 0 || len(in.SecurityGroups) > 0 || in.PrivateIpAddress != nil) {
		return plan, failure("InvalidParameterCombination", "Network interfaces and instance-level network parameters may not be specified on the same request")
	}
	if len(in.NetworkInterfaces) > 1 {
		return plan, unsupported("Only one primary IPv4 network interface is supported.")
	}
	spec := api.InstanceNetworkInterfaceSpecification{DeviceIndex: new(api.Integer(0)), SubnetId: new(api.String(str(in.SubnetId))), Groups: in.SecurityGroupIds, PrivateIpAddress: in.PrivateIpAddress}
	if len(in.NetworkInterfaces) == 1 {
		spec = api.CloneInstanceNetworkInterfaceSpecification(in.NetworkInterfaces[0])
	}
	if spec.DeviceIndex == nil || *spec.DeviceIndex != 0 {
		return plan, failure("InvalidParameterValue", "The primary interface must have device index zero.")
	}
	if spec.NetworkCardIndex != nil && *spec.NetworkCardIndex != 0 {
		return plan, unsupported("Multiple network cards are not supported.")
	}
	if boolValue(spec.AssociateCarrierIpAddress) {
		return plan, unsupported("Carrier IPv4 allocation is not implemented.")
	}
	if len(spec.PrivateIpAddresses) == 1 && boolValue(spec.PrivateIpAddresses[0].Primary) {
		if spec.PrivateIpAddress != nil {
			return plan, failure("InvalidParameterCombination", "Specify the primary private IP address only once.")
		}
		spec.PrivateIpAddress = spec.PrivateIpAddresses[0].PrivateIpAddress
		spec.PrivateIpAddresses = nil
	}
	if spec.ConnectionTrackingSpecification != nil || spec.EnaQueueCount != nil || spec.EnaSrdSpecification != nil || spec.Ipv4PrefixCount != nil || len(spec.Ipv4Prefixes) > 0 || spec.Ipv6AddressCount != nil || len(spec.Ipv6Addresses) > 0 || spec.Ipv6PrefixCount != nil || len(spec.Ipv6Prefixes) > 0 || spec.PrimaryIpv6 != nil || len(spec.PrivateIpAddresses) > 0 || spec.SecondaryPrivateIpAddressCount != nil {
		return plan, unsupported("Secondary addresses, IPv6, prefixes and advanced network interface controls are not implemented for instances.")
	}
	if spec.InterfaceType != nil && str(spec.InterfaceType) != "interface" {
		return plan, unsupported("Only ordinary network interfaces are supported.")
	}
	if err := validateNetworkInterfaceDescription(str(spec.Description)); err != nil {
		return plan, err
	}
	if str(spec.NetworkInterfaceId) != "" {
		if boolValue(spec.AssociatePublicIpAddress) {
			return plan, failure("InvalidParameterCombination", "An existing network interface cannot request automatic public IPv4 at launch.")
		}
		if str(spec.SubnetId) != "" || len(spec.Groups) > 0 || spec.PrivateIpAddress != nil || spec.Description != nil {
			return plan, failure("InvalidParameterCombination", "An existing interface cannot be combined with subnet, groups, description or private IP parameters.")
		}
		eni, err := tx.NetworkInterface(key(ctx, str(spec.NetworkInterfaceId)))
		if errors.Is(err, ErrNotFound) {
			return plan, missing("network-interface", str(spec.NetworkInterfaceId))
		}
		if err != nil {
			return plan, err
		}
		if len(eni.Data.PrivateIpAddresses) > 1 || len(eni.Data.Ipv6Addresses) > 0 {
			return plan, unsupported("Instance attachment of interfaces with secondary or IPv6 addresses is not implemented.")
		}
		if *in.MaxCount != 1 {
			return plan, failure("InvalidParameterCombination", "An existing interface may be used for only one instance.")
		}
		plan.existing = &eni
		spec.SubnetId = eni.Data.SubnetId
		for _, g := range eni.Data.Groups {
			spec.Groups = append(spec.Groups, api.SecurityGroupId(str(g.GroupId)))
		}
		if spec.DeleteOnTermination == nil {
			spec.DeleteOnTermination = new(api.Boolean(false))
		}
	}
	if str(spec.SubnetId) == "" {
		subnets, err := tx.Subnets(scopeFor(ctx))
		if err != nil {
			return plan, err
		}
		for _, subnet := range subnets {
			if !boolValue(subnet.Data.DefaultForAz) {
				continue
			}
			if in.Placement != nil {
				if str(in.Placement.AvailabilityZone) != "" && str(in.Placement.AvailabilityZone) != str(subnet.Data.AvailabilityZone) {
					continue
				}
				if str(in.Placement.AvailabilityZoneId) != "" && str(in.Placement.AvailabilityZoneId) != str(subnet.Data.AvailabilityZoneId) {
					continue
				}
			}
			spec.SubnetId = subnet.Data.SubnetId
			break
		}
		if str(spec.SubnetId) == "" {
			return plan, failure("VPCIdNotSpecified", "No default VPC subnet is available; specify a subnet.")
		}
	}
	subnet, err := s.subnetForUse(ctx, tx, str(spec.SubnetId), "RunInstances")
	if err != nil {
		return plan, err
	}
	if in.Placement != nil && str(in.Placement.AvailabilityZone) != "" && str(in.Placement.AvailabilityZone) != str(subnet.Data.AvailabilityZone) {
		return plan, failure("InvalidParameterValue", "The subnet and availability zone do not match.")
	}
	// IAM observes request presence, not the subsequently resolved subnet
	// default. BoolIfExists can therefore require an explicit false request.
	publicIPRequest := spec.AssociatePublicIpAddress
	if spec.AssociatePublicIpAddress == nil && plan.existing == nil {
		spec.AssociatePublicIpAddress = new(api.Boolean(boolValue(subnet.Data.MapPublicIpOnLaunch)))
	}
	if err := s.authorizeSubnetUse(ctx, "RunInstances", subnet); err != nil {
		return plan, err
	}
	groups, err := s.networkInterfaceGroups(ctx, tx, "RunInstances", spec.Groups, str(subnet.Data.VpcId))
	if err != nil {
		return plan, err
	}
	if err := validateNetworkInterfaceGroups(groups, subnet, true); err != nil {
		return plan, err
	}
	conditions := vpcConditions(subnet.Key.Scope, str(subnet.Data.VpcId))
	conditions["ec2:Subnet"] = []string{resourceARN(subnet.Key.Scope, "subnet", subnet.Key.ID)}
	if publicIPRequest != nil {
		conditions["ec2:AssociatePublicIpAddress"] = []string{strconv.FormatBool(boolValue(publicIPRequest))}
	}
	if plan.existing != nil {
		err = s.authorizeWith(ctx, "RunInstances", "network-interface", plan.existing.Key.ID, plan.existing.Data.TagSet, conditions)
	} else {
		err = s.authorizeCreateWith(ctx, "RunInstances", "network-interface", "*", tags, conditions)
	}
	if err != nil {
		return plan, err
	}
	if plan.existing != nil && len(tags) > 0 {
		return plan, failure("InvalidParameterCombination", "Network interface launch tags require a newly created interface.")
	}
	if spec.DeleteOnTermination == nil {
		spec.DeleteOnTermination = new(api.Boolean(true))
	}
	plan.subnet, plan.groups, plan.spec = subnet, groups, spec
	return plan, nil
}

func (s *Service) admitInstanceNetwork(ctx context.Context, tx Transaction, id string, plan instanceNetworkPlan, tags api.TagList) (api.InstanceNetworkInterface, error) {
	var record NetworkInterfaceRecord
	if plan.existing != nil {
		record = *plan.existing
		if record.Data.Attachment != nil || str(record.Data.Status) != "available" || record.TaskOwnerARN != "" || boolValue(record.Data.RequesterManaged) {
			return api.InstanceNetworkInterface{}, failure("InvalidNetworkInterface.InUse", "The interface is already in use.")
		}
	} else {
		pool, err := networkInterfaceAddressPool(ctx, tx, plan.subnet)
		if err != nil {
			return api.InstanceNetworkInterface{}, err
		}
		ip := str(plan.spec.PrivateIpAddress)
		if ip != "" {
			err = pool.reserveExplicit(ip, true)
		} else {
			ip, err = pool.allocate()
		}
		if err != nil {
			return api.InstanceNetworkInterface{}, err
		}
		eniID, err := tx.NextID(scopeFor(ctx), "eni")
		if err != nil {
			return api.InstanceNetworkInterface{}, err
		}
		digest := sha256.Sum256([]byte(resourceARN(scopeFor(ctx), "network-interface", eniID)))
		record = NetworkInterfaceRecord{Key: key(ctx, eniID), SubnetOwnerAccountID: plan.subnet.Key.Scope.AccountID, Data: api.NetworkInterface{
			NetworkInterfaceId: new(api.String(eniID)), SubnetId: plan.subnet.Data.SubnetId, VpcId: plan.subnet.Data.VpcId,
			AvailabilityZone: plan.subnet.Data.AvailabilityZone, AvailabilityZoneId: plan.subnet.Data.AvailabilityZoneId,
			OwnerId: new(api.String(scopeFor(ctx).AccountID)), RequesterManaged: new(api.Boolean(false)), Description: plan.spec.Description,
			InterfaceType: new(api.NetworkInterfaceType("interface")), MacAddress: new(api.String(fmt.Sprintf("02:%02x:%02x:%02x:%02x:%02x", digest[0], digest[1], digest[2], digest[3], digest[4]))),
			PrivateIpAddress: new(api.String(ip)), PrivateIpAddresses: api.NetworkInterfacePrivateIpAddressList{newNetworkInterfaceAddress(ip, true)}, Groups: networkInterfaceGroupIdentifiers(plan.groups), SourceDestCheck: new(api.Boolean(true)), TagSet: tags,
		}}
		current, err := tx.Subnet(plan.subnet.Key)
		if err != nil {
			return api.InstanceNetworkInterface{}, err
		}
		if err := changeNetworkInterfaceCapacity(tx, current, -1); err != nil {
			return api.InstanceNetworkInterface{}, err
		}
	}
	attachmentID, err := tx.NextID(scopeFor(ctx), "eni-attach")
	if err != nil {
		return api.InstanceNetworkInterface{}, err
	}
	record.Data.Status = new(api.NetworkInterfaceStatus("in-use"))
	record.Data.Attachment = &api.NetworkInterfaceAttachment{AttachmentId: new(api.String(attachmentID)), InstanceId: new(api.String(id)), InstanceOwnerId: new(api.String(scopeFor(ctx).AccountID)), DeviceIndex: new(api.Integer(0)), NetworkCardIndex: new(api.Integer(0)), Status: new(api.AttachmentStatus("attached")), AttachTime: new(api.DateTime(s.clock.Now())), DeleteOnTermination: plan.spec.DeleteOnTermination}
	if err := tx.PutNetworkInterface(record); err != nil {
		return api.InstanceNetworkInterface{}, err
	}
	if boolValue(plan.spec.AssociatePublicIpAddress) {
		if err := admitAutomaticPublicIPv4(ctx, tx, record); err != nil {
			return api.InstanceNetworkInterface{}, err
		}
	}
	record.Data, err = networkInterfaceProjection(ctx, tx, record)
	if err != nil {
		return api.InstanceNetworkInterface{}, err
	}
	return instanceNetworkData(record.Data), nil
}

func instanceNetworkData(eni api.NetworkInterface) api.InstanceNetworkInterface {
	out := api.InstanceNetworkInterface{NetworkInterfaceId: eni.NetworkInterfaceId, SubnetId: eni.SubnetId, VpcId: eni.VpcId, OwnerId: eni.OwnerId, MacAddress: eni.MacAddress, PrivateIpAddress: eni.PrivateIpAddress, PrivateDnsName: eni.PrivateDnsName, Description: eni.Description, Status: eni.Status, SourceDestCheck: eni.SourceDestCheck, Groups: eni.Groups, InterfaceType: new(api.String(str(eni.InterfaceType)))}
	if a := eni.Attachment; a != nil {
		out.Attachment = &api.InstanceNetworkInterfaceAttachment{AttachmentId: a.AttachmentId, DeviceIndex: a.DeviceIndex, NetworkCardIndex: a.NetworkCardIndex, AttachTime: a.AttachTime, DeleteOnTermination: a.DeleteOnTermination, Status: a.Status}
	}
	if a := eni.Association; a != nil {
		out.Association = &api.InstanceNetworkInterfaceAssociation{CarrierIp: a.CarrierIp, CustomerOwnedIp: a.CustomerOwnedIp, IpOwnerId: a.IpOwnerId, PublicDnsName: a.PublicDnsName, PublicIp: a.PublicIp}
	}
	for _, ip := range eni.PrivateIpAddresses {
		address := api.InstancePrivateIpAddress{PrivateIpAddress: ip.PrivateIpAddress, PrivateDnsName: ip.PrivateDnsName, Primary: ip.Primary}
		if a := ip.Association; a != nil {
			address.Association = &api.InstanceNetworkInterfaceAssociation{CarrierIp: a.CarrierIp, CustomerOwnedIp: a.CustomerOwnedIp, IpOwnerId: a.IpOwnerId, PublicDnsName: a.PublicDnsName, PublicIp: a.PublicIp}
		}
		out.PrivateIpAddresses = append(out.PrivateIpAddresses, address)
	}
	return out
}

func releaseInstanceNetworks(ctx context.Context, tx Transaction, record InstanceRecord) error {
	for _, attached := range record.Data.NetworkInterfaces {
		eni, err := tx.NetworkInterface(key(ctx, str(attached.NetworkInterfaceId)))
		if errors.Is(err, ErrNotFound) {
			continue
		}
		if err != nil {
			return err
		}
		if eni.Data.Attachment == nil || str(eni.Data.Attachment.InstanceId) != record.Key.ID {
			return failure("IncorrectState", "The instance no longer owns its network interface.")
		}
		if boolValue(eni.Data.Attachment.DeleteOnTermination) {
			if err := releaseInterfacePublicAddresses(ctx, tx, eni.Key.ID, true); err != nil {
				return err
			}
			subnet, err := interfaceSubnet(tx, eni)
			if err != nil {
				return err
			}
			if err := changeNetworkInterfaceCapacity(tx, subnet, len(eni.Data.PrivateIpAddresses)); err != nil {
				return err
			}
			if err := tx.DeleteNetworkInterface(eni.Key); err != nil {
				return err
			}
		} else {
			addresses, err := tx.PublicAddresses(scopeFor(ctx))
			if err != nil {
				return err
			}
			for _, address := range addresses {
				if address.Automatic && str(address.Data.NetworkInterfaceId) == eni.Key.ID {
					if err := tx.DeletePublicAddress(address.Key); err != nil {
						return err
					}
				}
			}
			eni.Data.Attachment = nil
			eni.Data.Status = new(api.NetworkInterfaceStatus("available"))
			if err := tx.PutNetworkInterface(eni); err != nil {
				return err
			}
		}
	}
	return nil
}
