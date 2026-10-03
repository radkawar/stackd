package ec2

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"

	api "stackd/internal/awsapi/ec2"
	"stackd/internal/awsctx"
)

func (s *Service) createNetworkInterface(ctx context.Context, tx Transaction, in *api.CreateNetworkInterfaceRequest) (*api.CreateNetworkInterfaceResult, error) {
	tags, err := CreationTags(in.TagSpecifications, "network-interface")
	if err != nil {
		return nil, err
	}
	if tags == nil {
		tags = api.TagList{}
	}
	subnet, err := s.subnetForUse(ctx, tx, str(in.SubnetId), "CreateNetworkInterface")
	if err != nil {
		return nil, err
	}
	conditions := vpcConditions(subnet.Key.Scope, str(subnet.Data.VpcId))
	conditions["ec2:Subnet"] = []string{resourceARN(subnet.Key.Scope, "subnet", subnet.Key.ID)}
	if err := s.authorizeCreateWith(ctx, "CreateNetworkInterface", "network-interface", "*", tags, conditions); err != nil {
		return nil, err
	}
	if err := s.authorizeSubnetUse(ctx, "CreateNetworkInterface", subnet); err != nil {
		return nil, err
	}
	groups, err := s.networkInterfaceGroups(ctx, tx, "CreateNetworkInterface", in.Groups, str(subnet.Data.VpcId))
	if err != nil {
		return nil, err
	}
	if err := dryRun(in.DryRun); err != nil {
		return nil, err
	}
	if subnet.Key.ID == "" {
		return nil, missing("subnet", str(in.SubnetId))
	}
	if err := validateNetworkInterfaceGroups(groups, subnet, true); err != nil {
		return nil, err
	}
	if in.ConnectionTrackingSpecification != nil || in.EnablePrimaryIpv6 != nil || in.Ipv4PrefixCount != nil || len(in.Ipv4Prefixes) > 0 || in.Ipv6AddressCount != nil || len(in.Ipv6Addresses) > 0 || in.Ipv6PrefixCount != nil || len(in.Ipv6Prefixes) > 0 || in.Operator != nil {
		// TODO: Comeback implement IPv6/prefix allocation, connection tracking and operator ownership.
		return nil, unsupported("IPv6, delegated prefixes, connection tracking and operator-managed interfaces are not implemented.")
	}
	if in.InterfaceType != nil && str(in.InterfaceType) != "interface" {
		switch str(in.InterfaceType) {
		case "efa", "efa-only", "trunk", "branch":
			// TODO: Comeback implement EFA and trunk/branch instance attachment state.
			return nil, unsupported("EFA, EFA-only, trunk and branch network interfaces are not implemented.")
		default:
			return nil, failure("InvalidParameterValue", "Value ("+str(in.InterfaceType)+") for parameter interfaceType is invalid.")
		}
	}
	if err := validateNetworkInterfaceDescription(str(in.Description)); err != nil {
		return nil, err
	}
	if err := validateSecondaryAddressCount(in.SecondaryPrivateIpAddressCount); err != nil {
		return nil, err
	}
	pool, err := networkInterfaceAddressPool(ctx, tx, subnet)
	if err != nil {
		return nil, err
	}
	addresses := api.NetworkInterfacePrivateIpAddressList{}
	primaryCount := 0
	if in.PrivateIpAddress != nil {
		primaryCount++
	}
	for _, address := range in.PrivateIpAddresses {
		if boolValue(address.Primary) {
			primaryCount++
		}
	}
	if primaryCount > 1 {
		return nil, failure("InvalidParameterValue", "Only one primary private IP address can be specified.")
	}
	if in.SecondaryPrivateIpAddressCount != nil && len(in.PrivateIpAddresses) > 0 && (len(in.PrivateIpAddresses) != 1 || !boolValue(in.PrivateIpAddresses[0].Primary)) {
		return nil, failure("InvalidParameterValue", "You can specify one and only one secondaryPrivateIpAddressCount or secondaryPrivateIpAddressCount or ipv4Prefixes or ipv4PrefixCount.")
	}
	explicit := make(map[string]bool, len(in.PrivateIpAddresses)+1)
	if in.PrivateIpAddress != nil {
		explicit[str(in.PrivateIpAddress)] = true
	}
	for _, address := range in.PrivateIpAddresses {
		ip, primary := str(address.PrivateIpAddress), boolValue(address.Primary)
		if previous, exists := explicit[ip]; exists {
			if previous != primary {
				return nil, failure("InvalidParameterValue", "address value can't be both primary and secondary")
			}
			return nil, failure("InvalidParameterValue", "Duplicate private IP address.")
		}
		explicit[ip] = primary
	}
	// Explicit addresses are checked before token equality, even on an identical
	// retry. Automatic allocation happens only after a retained outcome is checked.
	for _, address := range in.PrivateIpAddresses {
		ip := str(address.PrivateIpAddress)
		if err := pool.reserveExplicit(ip, false); err != nil {
			return nil, err
		}
		addresses = append(addresses, newNetworkInterfaceAddress(ip, boolValue(address.Primary)))
	}
	if in.PrivateIpAddress != nil {
		ip := str(in.PrivateIpAddress)
		if err := pool.reserveExplicit(ip, false); err != nil {
			return nil, err
		}
		addresses = append(addresses, newNetworkInterfaceAddress(ip, true))
	}
	admitted := admittedNetworkInterfaceCreation(in)
	token := strings.TrimSpace(str(in.ClientToken))
	for _, character := range str(in.ClientToken) {
		if (character < 32 && character != '\t' && character != '\n' && character != '\r') || character == 0xfffe || character == 0xffff {
			return nil, failure("InvalidCharacter", "ClientToken contains an invalid XML character.")
		}
	}
	if in.ClientToken != nil && token == "" {
		// TODO: Comeback resolve native blank-token admission. AWS fails internally;
		// reject unsupported input instead of manufacturing an internal failure.
		return nil, unsupported("Blank ClientToken requests are not supported.")
	}
	// TODO: Comeback establish token retention bounds and resolve the captured
	// case-only mismatch anomaly. Follow the documented case-sensitive contract.
	creationKey := NetworkInterfaceCreationKey{Scope: scopeFor(ctx), Token: token}
	if token != "" {
		previous, err := tx.NetworkInterfaceCreation(creationKey)
		if err == nil {
			if !reflect.DeepEqual(previous.Input, admitted) {
				return nil, networkInterfaceTokenMismatch()
			}
			record, err := tx.NetworkInterface(key(ctx, previous.ResourceID))
			if errors.Is(err, ErrNotFound) {
				return nil, networkInterfaceTokenMismatch()
			}
			if err != nil {
				return nil, err
			}
			return networkInterfaceCreationResult(record.Data, tags), nil
		}
		if !errors.Is(err, ErrNotFound) {
			return nil, err
		}
	}
	if primaryCount == 0 {
		ip, err := pool.allocate()
		if err != nil {
			return nil, err
		}
		addresses = append(addresses, newNetworkInterfaceAddress(ip, true))
	}
	if in.SecondaryPrivateIpAddressCount != nil {
		for range int(*in.SecondaryPrivateIpAddressCount) {
			ip, err := pool.allocate()
			if err != nil {
				return nil, err
			}
			addresses = append(addresses, newNetworkInterfaceAddress(ip, false))
		}
	}
	id, err := tx.NextID(scopeFor(ctx), "eni")
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256([]byte(resourceARN(scopeFor(ctx), "network-interface", id)))
	mac := fmt.Sprintf("02:%02x:%02x:%02x:%02x:%02x", digest[0], digest[1], digest[2], digest[3], digest[4])
	data := api.NetworkInterface{
		NetworkInterfaceId: new(api.String(id)), SubnetId: copyPointer(subnet.Data.SubnetId), VpcId: copyPointer(subnet.Data.VpcId),
		AvailabilityZone: copyPointer(subnet.Data.AvailabilityZone), AvailabilityZoneId: copyPointer(subnet.Data.AvailabilityZoneId),
		OwnerId: new(api.String(scopeFor(ctx).AccountID)), RequesterId: new(api.String(awsctx.FromContext(ctx).PrincipalID)),
		RequesterManaged: new(api.Boolean(false)), Description: new(api.String(str(in.Description))),
		InterfaceType: new(api.NetworkInterfaceType("interface")), MacAddress: new(api.String(mac)),
		Status: new(api.NetworkInterfaceStatus("available")), SourceDestCheck: new(api.Boolean(true)),
		Groups: networkInterfaceGroupIdentifiers(groups), PrivateIpAddresses: addresses,
		Ipv6Addresses: api.NetworkInterfaceIpv6AddressesList{}, TagSet: tags,
	}
	for _, address := range addresses {
		if boolValue(address.Primary) {
			data.PrivateIpAddress = copyPointer(address.PrivateIpAddress)
			break
		}
	}
	if err := changeNetworkInterfaceCapacity(tx, subnet, -len(addresses)); err != nil {
		return nil, err
	}
	record := NetworkInterfaceRecord{Key: key(ctx, id), Data: data, SubnetOwnerAccountID: subnet.Key.Scope.AccountID}
	if mappingARN, managed := ctx.Value(lambdaSourceNetworkOwnerKey{}).(string); managed {
		record.LambdaMappingOwnerARN = mappingARN
		record.Data.RequesterManaged = new(api.Boolean(true))
		record.Data.RequesterId = nil
		record.Data.Status = new(api.NetworkInterfaceStatus("in-use"))
		record.Data.InterfaceType = new(api.NetworkInterfaceType("lambda"))
	}
	if err := tx.PutNetworkInterface(record); err != nil {
		return nil, err
	}
	if token != "" {
		if err := tx.PutNetworkInterfaceCreation(NetworkInterfaceCreationRecord{Key: creationKey, ResourceID: id, Input: admitted}); err != nil {
			return nil, err
		}
	}
	return networkInterfaceCreationResult(record.Data, tags), nil
}

func admittedNetworkInterfaceCreation(in *api.CreateNetworkInterfaceRequest) api.CreateNetworkInterfaceRequest {
	out := api.CloneCreateNetworkInterfaceRequest(api.CreateNetworkInterfaceRequest{
		SubnetId: in.SubnetId, Description: new(api.String(str(in.Description))), Groups: in.Groups,
		InterfaceType: in.InterfaceType, PrivateIpAddress: in.PrivateIpAddress,
		PrivateIpAddresses: in.PrivateIpAddresses, SecondaryPrivateIpAddressCount: in.SecondaryPrivateIpAddressCount,
	})
	if len(out.Groups) == 0 {
		out.Groups = nil
	} else {
		slices.Sort(out.Groups)
		out.Groups = slices.Compact(out.Groups)
	}
	if len(out.PrivateIpAddresses) == 0 {
		out.PrivateIpAddresses = nil
	}
	return out
}

func networkInterfaceTokenMismatch() error {
	return failure("IdempotentParameterMismatch", "Arguments on this idempotent request are inconsistent with arguments used in previous request(s).")
}

func networkInterfaceCreationResult(data api.NetworkInterface, tags api.TagList) *api.CreateNetworkInterfaceResult {
	data.Status = new(api.NetworkInterfaceStatus("pending"))
	data.TagSet = tags
	data.PublicDnsName = nil
	data.Operator = &api.OperatorResponse{Managed: new(api.Boolean(false))}
	return &api.CreateNetworkInterfaceResult{NetworkInterface: &data}
}

func validateNetworkInterfaceDescription(description string) error {
	valid := len(description) < 256
	for _, char := range description {
		if !((char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') || (char >= '0' && char <= '9') || strings.ContainsRune(". _-:/()#,@[]+=&;{}!$*", char)) {
			valid = false
			break
		}
	}
	if !valid {
		return failure("InvalidParameterValue", "Invalid interface description. Valid descriptions are strings less than 256 characters from the following set:  a-zA-Z0-9. _-:/()#,@[]+=&;{}!$*")
	}
	return nil
}

// Authorize every requested security group, including the resolved VPC default,
// before DryRun or membership validation, for both creation and replacement.
func (s *Service) networkInterfaceGroups(ctx context.Context, tx Reader, action string, ids api.SecurityGroupIdStringList, vpcID string) ([]SecurityGroupRecord, error) {
	if len(ids) == 0 {
		groups, err := tx.SecurityGroups(scopeFor(ctx))
		if err != nil {
			return nil, err
		}
		for _, group := range groups {
			if str(group.Data.VpcId) == vpcID && str(group.Data.GroupName) == "default" {
				ids = api.SecurityGroupIdStringList{api.SecurityGroupId(group.Key.ID)}
				break
			}
		}
	}
	groups := make([]SecurityGroupRecord, 0, len(ids))
	seen := make(map[string]bool, len(ids))
	for _, rawID := range ids {
		id := string(rawID)
		if seen[id] {
			continue
		}
		seen[id] = true
		group, err := tx.SecurityGroup(key(ctx, id))
		if err != nil && !errors.Is(err, ErrNotFound) {
			return nil, err
		}
		if err := s.authorizeWith(ctx, action, "security-group", id, group.Data.Tags, vpcConditions(groupVPCScope(group), str(group.Data.VpcId))); err != nil {
			return nil, err
		}
		// Retain the requested ID for a useful missing-group error after DryRun.
		if errors.Is(err, ErrNotFound) {
			group.Key = key(ctx, id)
		}
		groups = append(groups, group)
	}
	return groups, nil
}

func validateNetworkInterfaceGroups(groups []SecurityGroupRecord, subnet SubnetRecord, creating bool) error {
	if len(groups) == 0 {
		return failure("InvalidGroup.NotFound", "Specify a security group owned by this account in the subnet's VPC.")
	}
	for _, group := range groups {
		if group.Data.GroupId == nil {
			return missing("security-group", group.Key.ID)
		}
		if str(group.Data.VpcId) != str(subnet.Data.VpcId) || groupVPCScope(group) != subnet.Key.Scope {
			if creating {
				return failure("InvalidParameterValue", "Security group "+group.Key.ID+" and subnet "+subnet.Key.ID+" belong to different networks.")
			}
			return failure("InvalidGroup.NotFound", "You have specified two resources that belong to different networks.")
		}
	}
	return nil
}

func networkInterfaceGroupIdentifiers(groups []SecurityGroupRecord) api.GroupIdentifierList {
	out := make(api.GroupIdentifierList, 0, len(groups))
	for _, group := range groups {
		out = append(out, api.GroupIdentifier{GroupId: copyPointer(group.Data.GroupId), GroupName: copyPointer(group.Data.GroupName)})
	}
	return out
}
