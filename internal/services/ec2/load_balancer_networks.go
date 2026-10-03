package ec2

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/netip"
	"strconv"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws/arn"

	"stackd/compute/network"
	"stackd/internal/apievents"
	api "stackd/internal/awsapi/ec2"
	"stackd/internal/awsctx"
)

// LoadBalancerNetwork is a current EC2-owned interface and its packet policy.
// ALB ownership uses the retained creation record, never the ECS task owner field.
// Interface supplies retained control identity; Network supplies current private
// and automatic public addressing, SG/NACL rules and attached-IGW route authority.
// ALB-specific AWS public association owner fields are not inferred here.
type LoadBalancerNetwork struct {
	Interface api.NetworkInterface
	Network   network.Specification
}

// LoadBalancerTarget binds a private address to its current ENI and attachment.
// OwnerARN is populated only for an actual ECS task or attached EC2 instance.
// A plain IP target in a retained subnet or outside-VPC private range has no
// invented InterfaceID, OwnerARN or Incarnation until EC2 actually owns that IP.
type LoadBalancerTarget struct {
	Address, AvailabilityZone, InterfaceID, OwnerARN, Incarnation string
}

func requireLoadBalancerNetworkService(ctx context.Context) error {
	m := awsctx.FromContext(ctx)
	role := "arn:" + m.Partition + ":iam::" + m.AccountID + ":role/aws-service-role/elasticloadbalancing.amazonaws.com/AWSServiceRoleForElasticLoadBalancing"
	if m.Partition == "" || m.AccountID == "" || m.Region == "" || m.InvokedBy != "elasticloadbalancing.amazonaws.com" || m.IssuerARN != role {
		return failure("AuthFailure", "Load balancer networks require the Elastic Load Balancing service-linked role.")
	}
	return nil
}

func validateLoadBalancerNetworkOwner(ctx context.Context, owner string) error {
	m := awsctx.FromContext(ctx)
	parsed, err := arn.Parse(owner)
	if err != nil || parsed.Partition != m.Partition || parsed.AccountID != m.AccountID || parsed.Region != m.Region || parsed.Service != "elasticloadbalancing" {
		return failure("InvalidParameterValue", "The load balancer must belong to the current scope.")
	}
	parts := strings.Split(parsed.Resource, "/")
	if len(parts) != 4 || parts[0] != "loadbalancer" || parts[1] != "app" || parts[2] == "" || parts[3] == "" {
		return failure("InvalidParameterValue", "An application load balancer ARN is required.")
	}
	return nil
}

func loadBalancerNetworkIdentity(owner, subnetID string, generation uint64, internetFacing bool) (string, string) {
	// ALB retains a generation before effects. Removing and later re-adding a
	// subnet gets a new generation; replay of a released generation cannot revive.
	scheme := "internal"
	if internetFacing {
		scheme = "internet-facing"
	}
	identity := loadBalancerNetworkPrefix(owner, subnetID) + strconv.FormatUint(generation, 10)
	description := identity + " scheme/" + scheme
	digest := sha256.Sum256([]byte(identity))
	return description, hex.EncodeToString(digest[:])
}

func loadBalancerNetworkPrefix(owner, subnetID string) string {
	return "ELB " + owner + " subnet/" + subnetID + " generation/"
}

func (s *Service) ValidateLoadBalancerVPC(ctx context.Context, vpcID string) error {
	if err := requireLoadBalancerNetworkService(ctx); err != nil {
		return err
	}
	return s.repository.View(ctx, func(tx Reader) error {
		ctx := tx.Context()
		if err := s.authorize(ctx, "DescribeVpcs", "", "*", nil); err != nil {
			return err
		}
		_, err := loadVPC(ctx, tx, vpcID)
		return err
	})
}

// DefaultLoadBalancerSecurityGroups resolves omitted ALB groups from the actual
// current VPC default, so ELB can retain and authorize the resulting group IDs.
func (s *Service) DefaultLoadBalancerSecurityGroups(ctx context.Context, vpcID string) ([]string, error) {
	if err := requireLoadBalancerNetworkService(ctx); err != nil {
		return nil, err
	}
	var ids []string
	err := s.repository.View(ctx, func(tx Reader) error {
		ctx := tx.Context()
		if err := s.authorize(ctx, "DescribeSecurityGroups", "", "*", nil); err != nil {
			return err
		}
		if _, err := loadVPC(ctx, tx, vpcID); err != nil {
			return err
		}
		groups, err := s.networkInterfaceGroups(ctx, tx, "CreateNetworkInterface", nil, vpcID)
		if err != nil {
			return err
		}
		if len(groups) == 0 {
			return failure("InvalidGroup.NotFound", "The VPC has no default security group.")
		}
		ids = make([]string, len(groups))
		for i, group := range groups {
			ids[i] = group.Key.ID
		}
		return nil
	})
	return ids, err
}

// ValidateLoadBalancerNetworks requires one standard, available AZ per subnet,
// with at least two distinct AZs and one VPC. Address reservation is allocation's
// responsibility; this read never consumes or fabricates subnet capacity.
func (s *Service) ValidateLoadBalancerNetworks(ctx context.Context, subnetIDs, groupIDs []string) (string, []SubnetRecord, error) {
	if err := requireLoadBalancerNetworkService(ctx); err != nil {
		return "", nil, err
	}
	var vpcID string
	var selected []SubnetRecord
	err := s.repository.View(ctx, func(tx Reader) error {
		ctx := tx.Context()
		for _, action := range []string{"DescribeSubnets", "DescribeSecurityGroups", "DescribeAvailabilityZones"} {
			if err := s.authorize(ctx, action, "", "*", nil); err != nil {
				return err
			}
		}
		if len(subnetIDs) < 2 {
			return failure("InvalidParameterValue", "An application load balancer requires subnets in at least two availability zones.")
		}
		zones, err := s.availableZones(ctx)
		if err != nil {
			return err
		}
		seen := make(map[string]bool, len(subnetIDs))
		for _, id := range subnetIDs {
			subnet, err := loadSubnet(ctx, tx, id)
			if err != nil {
				return err
			}
			if err := loadBalancerSubnetZone(subnet, zones); err != nil {
				return err
			}
			zoneID := str(subnet.Data.AvailabilityZoneId)
			if seen[zoneID] {
				return failure("InvalidParameterValue", "Only one subnet per availability zone may be selected.")
			}
			seen[zoneID] = true
			if vpcID != "" && vpcID != str(subnet.Data.VpcId) {
				return failure("InvalidParameterValue", "Load balancer subnets must belong to the same VPC.")
			}
			vpcID = str(subnet.Data.VpcId)
			groups, err := s.networkInterfaceGroups(ctx, tx, "CreateNetworkInterface", taskGroupIDs(groupIDs), vpcID)
			if err != nil {
				return err
			}
			if err := validateNetworkInterfaceGroups(groups, subnet, true); err != nil {
				return err
			}
			selected = append(selected, subnet)
		}
		_, err = loadVPC(ctx, tx, vpcID)
		return err
	})
	return vpcID, selected, err
}

func loadBalancerSubnetZone(subnet SubnetRecord, zones api.AvailabilityZoneList) error {
	if str(subnet.Data.State) != "available" || str(subnet.Data.OutpostArn) != "" {
		return failure("InvalidParameterValue", "Load balancer subnets must be available standard availability-zone subnets.")
	}
	for _, zone := range zones {
		if str(zone.ZoneId) == str(subnet.Data.AvailabilityZoneId) && str(zone.ZoneName) == str(subnet.Data.AvailabilityZone) && str(zone.ZoneType) == "availability-zone" && str(zone.State) == "available" && str(zone.OptInStatus) != "not-opted-in" {
			return nil
		}
	}
	return failure("InvalidParameterValue", "The subnet is not in an available standard availability zone.")
}

func (s *Service) AllocateLoadBalancerNetwork(ctx context.Context, owner, subnetID string, generation uint64, internetFacing bool, groupIDs []string) (LoadBalancerNetwork, error) {
	var out LoadBalancerNetwork
	if err := requireLoadBalancerNetworkService(ctx); err != nil {
		return out, err
	}
	if err := validateLoadBalancerNetworkOwner(ctx, owner); err != nil {
		return out, err
	}
	if generation == 0 {
		return out, failure("InvalidParameterValue", "A retained load balancer attachment generation is required.")
	}
	description, token := loadBalancerNetworkIdentity(owner, subnetID, generation, internetFacing)
	request := &api.CreateNetworkInterfaceRequest{SubnetId: new(api.SubnetId(subnetID)), Description: new(api.String(description)), Groups: taskGroupIDs(groupIDs), ClientToken: new(api.String(token))}
	var err error
	ctx, err = apievents.Reserve(ctx)
	if err != nil {
		return out, err
	}
	err = s.repository.Update(ctx, func(tx Transaction) error {
		ctx := tx.Context()
		subnet, err := loadSubnet(ctx, tx, subnetID)
		if err != nil {
			return err
		}
		zones, err := s.availableZones(ctx)
		if err != nil {
			return err
		}
		if err := loadBalancerSubnetZone(subnet, zones); err != nil {
			return err
		}
		previous, lookupErr := tx.NetworkInterfaceCreation(NetworkInterfaceCreationKey{Scope: scopeFor(ctx), Token: token})
		if lookupErr != nil && !errors.Is(lookupErr, ErrNotFound) {
			return lookupErr
		}
		if lookupErr == nil {
			retained, err := ownedLoadBalancerInterface(ctx, tx, owner, previous.ResourceID)
			if err != nil {
				return err
			}
			if str(retained.Data.Description) != description {
				return networkInterfaceTokenMismatch()
			}
		} else {
			interfaces, err := tx.NetworkInterfaces(scopeFor(ctx))
			if err != nil {
				return err
			}
			prefix := loadBalancerNetworkPrefix(owner, subnetID)
			for _, record := range interfaces {
				if record.TaskOwnerARN == "" && boolValue(record.Data.RequesterManaged) && strings.HasPrefix(str(record.Data.Description), prefix) {
					return failure("InvalidParameterValue", "The load balancer subnet still has an active network interface generation.")
				}
			}
		}
		created, err := s.createNetworkInterface(ctx, tx, request)
		if err != nil {
			return err
		}
		record, err := tx.NetworkInterface(key(ctx, str(created.NetworkInterface.NetworkInterfaceId)))
		if err != nil {
			return err
		}
		if errors.Is(lookupErr, ErrNotFound) {
			record.Data.RequesterManaged = new(api.Boolean(true))
			record.Data.RequesterId = nil // No invented AWS-owned service account ID.
			record.Data.Status = new(api.NetworkInterfaceStatus("in-use"))
			if err := tx.PutNetworkInterface(record); err != nil {
				return err
			}
			if internetFacing {
				if err := admitAutomaticPublicIPv4(ctx, tx, record); err != nil {
					return err
				}
			}
			projection := api.CloneNetworkInterface(record.Data)
			projection.Status = new(api.NetworkInterfaceStatus("pending"))
			if err := s.recordCall(ctx, "CreateNetworkInterface", request, &api.CreateNetworkInterfaceResult{NetworkInterface: &projection}, nil); err != nil {
				return err
			}
		}
		out.Interface = record.Data
		out.Network, err = networkSpecification(ctx, tx, record)
		return err
	})
	return out, err
}

func ownedLoadBalancerInterface(ctx context.Context, tx Reader, owner, id string) (NetworkInterfaceRecord, error) {
	record, err := tx.NetworkInterface(key(ctx, id))
	if err != nil {
		return record, err
	}
	identity, matches := strings.CutPrefix(str(record.Data.Description), loadBalancerNetworkPrefix(owner, str(record.Data.SubnetId)))
	rawGeneration, scheme, hasScheme := strings.Cut(identity, " scheme/")
	generation, parseErr := strconv.ParseUint(rawGeneration, 10, 64)
	if !matches || parseErr != nil || generation == 0 || !hasScheme || (scheme != "internal" && scheme != "internet-facing") {
		return record, failure("AuthFailure", "The network interface is not owned by this load balancer attachment generation.")
	}
	description, token := loadBalancerNetworkIdentity(owner, str(record.Data.SubnetId), generation, scheme == "internet-facing")
	if record.TaskOwnerARN != "" || !boolValue(record.Data.RequesterManaged) || str(record.Data.Description) != description || str(record.Data.Status) != "in-use" || record.Data.Attachment != nil {
		return record, failure("AuthFailure", "The network interface is not owned by this load balancer incarnation.")
	}
	creation, err := tx.NetworkInterfaceCreation(NetworkInterfaceCreationKey{Scope: scopeFor(ctx), Token: token})
	if errors.Is(err, ErrNotFound) {
		return record, failure("AuthFailure", "The network interface has no matching load balancer creation record.")
	}
	if err != nil {
		return record, err
	}
	if creation.ResourceID != record.Key.ID || str(creation.Input.Description) != description || str(creation.Input.SubnetId) != str(record.Data.SubnetId) {
		return record, failure("AuthFailure", "The network interface creation does not belong to this load balancer incarnation.")
	}
	return record, nil
}

func (s *Service) ObserveLoadBalancerNetwork(ctx context.Context, owner, id string) (LoadBalancerNetwork, error) {
	var out LoadBalancerNetwork
	if err := requireLoadBalancerNetworkService(ctx); err != nil {
		return out, err
	}
	if err := validateLoadBalancerNetworkOwner(ctx, owner); err != nil {
		return out, err
	}
	err := s.repository.View(ctx, func(tx Reader) error {
		ctx := tx.Context()
		if err := s.authorize(ctx, "DescribeNetworkInterfaces", "", "*", nil); err != nil {
			return err
		}
		record, err := ownedLoadBalancerInterface(ctx, tx, owner, id)
		if err != nil {
			return err
		}
		out.Interface = record.Data
		out.Network, err = networkSpecification(ctx, tx, record)
		return err
	})
	return out, err
}

// SetLoadBalancerSecurityGroups is the service-owned groupSet mutation for an
// exact ALB ENI. Public ModifyNetworkInterfaceAttribute remains unable to modify
// requester-managed interfaces; the same EC2 group and action authority applies.
func (s *Service) SetLoadBalancerSecurityGroups(ctx context.Context, owner, id string, groupIDs []string) (LoadBalancerNetwork, error) {
	var out LoadBalancerNetwork
	if err := requireLoadBalancerNetworkService(ctx); err != nil {
		return out, err
	}
	if err := validateLoadBalancerNetworkOwner(ctx, owner); err != nil {
		return out, err
	}
	var err error
	ctx, err = apievents.Reserve(ctx)
	if err != nil {
		return out, err
	}
	err = s.repository.Update(ctx, func(tx Transaction) error {
		ctx := tx.Context()
		record, err := ownedLoadBalancerInterface(ctx, tx, owner, id)
		if err != nil {
			return err
		}
		if err := s.authorize(ctx, "ModifyNetworkInterfaceAttribute", "network-interface", id, record.Data.TagSet); err != nil {
			return err
		}
		groups, err := s.networkInterfaceGroups(ctx, tx, "ModifyNetworkInterfaceAttribute", taskGroupIDs(groupIDs), str(record.Data.VpcId))
		if err != nil {
			return err
		}
		subnet, err := interfaceSubnet(tx, record)
		if err != nil {
			return err
		}
		if err := validateNetworkInterfaceGroups(groups, subnet, false); err != nil {
			return err
		}
		changed := len(groups) != len(record.Data.Groups)
		for _, group := range groups {
			found := false
			for _, member := range record.Data.Groups {
				if group.Key.ID == str(member.GroupId) {
					found = true
					break
				}
			}
			changed = changed || !found
		}
		if changed {
			record.Data.Groups = networkInterfaceGroupIdentifiers(groups)
			if err := tx.PutNetworkInterface(record); err != nil {
				return err
			}
			ids := make(api.SecurityGroupIdStringList, len(groups))
			for i, group := range groups {
				ids[i] = api.SecurityGroupId(group.Key.ID)
			}
			request := &api.ModifyNetworkInterfaceAttributeRequest{NetworkInterfaceId: new(api.NetworkInterfaceId(id)), Groups: ids}
			if err := s.recordCall(ctx, "ModifyNetworkInterfaceAttribute", request, &emptyResult{}, nil); err != nil {
				return err
			}
		}
		out.Interface = record.Data
		out.Network, err = networkSpecification(ctx, tx, record)
		return err
	})
	return out, err
}

func (s *Service) ReleaseLoadBalancerNetwork(ctx context.Context, owner, id string) error {
	if err := requireLoadBalancerNetworkService(ctx); err != nil {
		return err
	}
	if err := validateLoadBalancerNetworkOwner(ctx, owner); err != nil {
		return err
	}
	var err error
	ctx, err = apievents.Reserve(ctx)
	if err != nil {
		return err
	}
	return s.repository.Update(ctx, func(tx Transaction) error {
		ctx := tx.Context()
		record, err := tx.NetworkInterface(key(ctx, id))
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		if err := s.authorize(ctx, "DeleteNetworkInterface", "network-interface", id, record.Data.TagSet); err != nil {
			return err
		}
		record, err = ownedLoadBalancerInterface(ctx, tx, owner, id)
		if err != nil {
			return err
		}
		subnet, err := interfaceSubnet(tx, record)
		if err != nil {
			return err
		}
		if err := changeNetworkInterfaceCapacity(tx, subnet, len(record.Data.PrivateIpAddresses)); err != nil {
			return err
		}
		if err := releaseInterfacePublicAddresses(ctx, tx, record.Key.ID, true); err != nil {
			return err
		}
		if err := tx.DeleteNetworkInterface(record.Key); err != nil {
			return err
		}
		return s.recordCall(ctx, "DeleteNetworkInterface", &api.DeleteNetworkInterfaceRequest{NetworkInterfaceId: new(api.NetworkInterfaceId(id))}, &emptyResult{}, nil)
	})
}

var loadBalancerSharedAddressRange = netip.MustParsePrefix("100.64.0.0/10")

func eligibleLoadBalancerAddress(value string) (netip.Addr, error) {
	address, err := netip.ParseAddr(value)
	if err != nil || !address.Is4() || !address.IsGlobalUnicast() || address.IsLoopback() || address.IsLinkLocalUnicast() {
		return netip.Addr{}, failure("InvalidParameterValue", "The target must be a unicast IPv4 address, not a loopback or link-local address.")
	}
	return address, nil
}

// ResolveLoadBalancerTarget uses current EC2 topology and any current ENI owner.
// Unallocated subnet IPs are valid AWS targets, but have no invented incarnation.
// Outside-VPC private targets return AZ "all"; ELB admission must require the
// caller's explicit availability-zone selection for those targets.
func (s *Service) ResolveLoadBalancerTarget(ctx context.Context, vpcID, targetType, targetID string) (LoadBalancerTarget, error) {
	var out LoadBalancerTarget
	if err := requireLoadBalancerNetworkService(ctx); err != nil {
		return out, err
	}
	err := s.repository.View(ctx, func(tx Reader) error {
		ctx := tx.Context()
		if err := s.authorize(ctx, "DescribeNetworkInterfaces", "", "*", nil); err != nil {
			return err
		}
		vpc, err := loadVPC(ctx, tx, vpcID)
		if err != nil {
			return err
		}
		address := targetID
		switch targetType {
		case "instance":
			if err := s.authorize(ctx, "DescribeInstances", "", "*", nil); err != nil {
				return err
			}
			instance, err := tx.Instance(key(ctx, targetID))
			if err != nil {
				return err
			}
			if str(instance.Data.VpcId) != vpcID || instanceState(instance) != "running" {
				return failure("InvalidParameterValue", "The target instance must be running in the target group VPC.")
			}
			address = str(instance.Data.PrivateIpAddress)
		case "ip":
		default:
			return failure("InvalidParameterValue", "Only instance and IP targets are supported.")
		}
		ip, err := eligibleLoadBalancerAddress(address)
		if err != nil {
			return err
		}
		interfaces, err := tx.NetworkInterfaces(scopeFor(ctx))
		if err != nil {
			return err
		}
		for _, record := range interfaces {
			if str(record.Data.VpcId) != vpcID {
				continue
			}
			for _, candidate := range record.Data.PrivateIpAddresses {
				if str(candidate.PrivateIpAddress) != ip.String() {
					continue
				}
				if targetType == "instance" && (record.Data.Attachment == nil || str(record.Data.Attachment.InstanceId) != targetID || taskInt(record.Data.Attachment.DeviceIndex, -1) != 0 || !boolValue(candidate.Primary)) {
					continue
				}
				endpoint, err := s.loadBalancerTargetInterface(ctx, tx, record, ip)
				if err != nil {
					return err
				}
				if out.InterfaceID != "" {
					return failure("InvalidParameterValue", "The target address has ambiguous network interface ownership.")
				}
				out = endpoint
			}
		}
		if out.InterfaceID == "" {
			if targetType == "instance" {
				return failure("InvalidParameterValue", "The instance target has no current primary network interface.")
			}
			out, err = s.loadBalancerSubnetTarget(ctx, tx, vpc, ip)
			return err
		}
		return nil
	})
	return out, err
}

func (s *Service) loadBalancerSubnetTarget(ctx context.Context, tx Reader, vpc VPCRecord, address netip.Addr) (LoadBalancerTarget, error) {
	if err := s.authorize(ctx, "DescribeSubnets", "", "*", nil); err != nil {
		return LoadBalancerTarget{}, err
	}
	subnets, err := tx.Subnets(scopeFor(ctx))
	if err != nil {
		return LoadBalancerTarget{}, err
	}
	for _, subnet := range subnets {
		if str(subnet.Data.VpcId) != vpc.Key.ID || str(subnet.Data.State) != "available" {
			continue
		}
		prefix, err := taskIPv4Prefix(str(subnet.Data.CidrBlock))
		if err != nil {
			return LoadBalancerTarget{}, err
		}
		if prefix.Contains(address) {
			return LoadBalancerTarget{Address: address.String(), AvailabilityZone: str(subnet.Data.AvailabilityZone)}, nil
		}
	}
	prefix, err := taskIPv4Prefix(str(vpc.Data.CidrBlock))
	if err != nil {
		return LoadBalancerTarget{}, err
	}
	if prefix.Contains(address) {
		return LoadBalancerTarget{}, failure("InvalidParameterValue", "The target address is within the VPC but not within a VPC subnet.")
	}
	if !address.IsPrivate() && !loadBalancerSharedAddressRange.Contains(address) {
		return LoadBalancerTarget{}, failure("InvalidParameterValue", "Outside-VPC targets require RFC1918 or RFC6598 private addresses.")
	}
	return LoadBalancerTarget{Address: address.String(), AvailabilityZone: "all"}, nil
}

func (s *Service) loadBalancerTargetInterface(ctx context.Context, tx Reader, record NetworkInterfaceRecord, address netip.Addr) (LoadBalancerTarget, error) {
	var out LoadBalancerTarget
	subnet, err := interfaceSubnet(tx, record)
	if err != nil {
		return out, err
	}
	prefix, err := taskIPv4Prefix(str(subnet.Data.CidrBlock))
	zoneMatches := str(subnet.Data.AvailabilityZoneId) == str(record.Data.AvailabilityZoneId)
	if str(subnet.Data.AvailabilityZoneId) == "" {
		zoneMatches = str(subnet.Data.AvailabilityZone) == str(record.Data.AvailabilityZone)
	}
	if err != nil || !prefix.Contains(address) || str(subnet.Data.VpcId) != str(record.Data.VpcId) || !zoneMatches {
		return out, failure("InvalidParameterValue", "The target address does not match its current subnet.")
	}
	out = LoadBalancerTarget{Address: address.String(), AvailabilityZone: str(record.Data.AvailabilityZone), InterfaceID: record.Key.ID, Incarnation: record.Key.ID}
	attachment := record.Data.Attachment
	if record.TaskOwnerARN != "" {
		if err := validateTaskNetworkOwner(ctx, record.TaskOwnerARN, str(record.Data.Description)); err != nil {
			return LoadBalancerTarget{}, err
		}
		if !boolValue(record.Data.RequesterManaged) || attachment == nil || str(attachment.InstanceId) != "" {
			return LoadBalancerTarget{}, failure("AuthFailure", "The target task does not own the current network interface attachment.")
		}
		out.OwnerARN = record.TaskOwnerARN
	} else if boolValue(record.Data.RequesterManaged) {
		return LoadBalancerTarget{}, failure("InvalidParameterValue", "A service-managed interface without a task target owner is not an eligible target.")
	}
	if attachment != nil {
		if str(record.Data.Status) != "in-use" || str(attachment.Status) != "attached" || str(attachment.AttachmentId) == "" {
			return LoadBalancerTarget{}, failure("InvalidParameterValue", "The target network interface attachment is not current.")
		}
		if id := str(attachment.InstanceId); id != "" {
			if err := s.authorize(ctx, "DescribeInstances", "", "*", nil); err != nil {
				return LoadBalancerTarget{}, err
			}
			instance, err := tx.Instance(key(ctx, id))
			if err != nil {
				return LoadBalancerTarget{}, err
			}
			if instanceState(instance) != "running" || str(instance.Data.VpcId) != str(record.Data.VpcId) {
				return LoadBalancerTarget{}, failure("InvalidParameterValue", "The target network interface's instance is not running in the target VPC.")
			}
			out.OwnerARN = resourceARN(scopeFor(ctx), "instance", id)
		}
	} else if str(record.Data.Status) != "available" {
		return LoadBalancerTarget{}, failure("InvalidParameterValue", "The target network interface is not available.")
	}
	return out, nil
}
