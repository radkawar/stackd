package ec2

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strconv"

	api "stackd/internal/awsapi/ec2"
)

func registerNetworkInterfaces(s *Service) {
	register(s, "CreateNetworkInterface", s.createNetworkInterface)
	register(s, "DescribeNetworkInterfaces", s.describeNetworkInterfaces)
	register(s, "DeleteNetworkInterface", s.deleteNetworkInterface)
	register(s, "DescribeNetworkInterfaceAttribute", s.describeNetworkInterfaceAttribute)
	register(s, "ModifyNetworkInterfaceAttribute", s.modifyNetworkInterfaceAttribute)
	register(s, "ResetNetworkInterfaceAttribute", s.resetNetworkInterfaceAttribute)
	register(s, "AssignPrivateIpAddresses", s.assignPrivateIpAddresses)
	register(s, "UnassignPrivateIpAddresses", s.unassignPrivateIpAddresses)
}

var networkInterfaceIDPattern = regexp.MustCompile(`^eni-(?:[0-9a-f]{8}|[0-9a-f]{17})$`)

func requireNetworkInterface(record NetworkInterfaceRecord, id string) error {
	if !networkInterfaceIDPattern.MatchString(id) {
		return failure("InvalidNetworkInterfaceId.Malformed", fmt.Sprintf("Invalid id: %q (expecting \"eni-...\")", id))
	}
	if record.Key.ID == "" {
		return missing("network-interface", id)
	}
	return nil
}

// Missing-resource checks follow authorization and DryRun, including for deleted
// IDs. Real storage failures must never be mistaken for missing resources.
func (s *Service) authorizeNetworkInterface(ctx context.Context, tx Reader, action, id string) (NetworkInterfaceRecord, error) {
	record, err := tx.NetworkInterface(key(ctx, id))
	if err != nil && !errors.Is(err, ErrNotFound) {
		return record, err
	}
	kind := "network-interface"
	tags := record.Data.TagSet
	if action == "DescribeNetworkInterfaceAttribute" {
		kind = ""
		tags = nil
	}
	conditions := vpcConditions(interfaceSubnetKey(record).Scope, str(record.Data.VpcId))
	if conditions != nil {
		conditions["ec2:Subnet"] = []string{resourceARN(interfaceSubnetKey(record).Scope, "subnet", str(record.Data.SubnetId))}
	}
	if err := s.authorizeWith(ctx, action, kind, id, tags, conditions); err != nil {
		return record, err
	}
	return record, nil
}

func (s *Service) describeNetworkInterfaces(ctx context.Context, tx Transaction, in *api.DescribeNetworkInterfacesRequest) (*api.DescribeNetworkInterfacesResult, error) {
	if err := s.authorize(ctx, "DescribeNetworkInterfaces", "", "*", nil); err != nil {
		return nil, err
	}
	if err := dryRun(in.DryRun); err != nil {
		return nil, err
	}
	records, err := s.visibleNetworkInterfaces(ctx, tx)
	if err != nil {
		return nil, err
	}
	items := make([]pageItem, 0, len(records))
	byID := make(map[string]api.NetworkInterface, len(records))
	for _, record := range records {
		d, err := networkInterfaceProjection(ctx, tx, record)
		if err != nil {
			return nil, err
		}
		fields := map[string][]string{
			"network-interface-id": {record.Key.ID}, "owner-id": {str(d.OwnerId)},
			"requester-id": {str(d.RequesterId)}, "requester-managed": {strconv.FormatBool(boolValue(d.RequesterManaged))},
			"availability-zone": {str(d.AvailabilityZone)}, "availability-zone-id": {str(d.AvailabilityZoneId)},
			"subnet-id": {str(d.SubnetId)}, "vpc-id": {str(d.VpcId)}, "mac-address": {str(d.MacAddress)},
			"description": {str(d.Description)}, "interface-type": {str(d.InterfaceType)},
			"source-dest-check": {strconv.FormatBool(boolValue(d.SourceDestCheck))}, "status": {str(d.Status)},
			"private-ip-address": {str(d.PrivateIpAddress)}, "private-dns-name": {str(d.PrivateDnsName)},
			"operator.managed": {"false"},
		}
		for _, group := range d.Groups {
			fields["group-id"] = append(fields["group-id"], str(group.GroupId))
			fields["group-name"] = append(fields["group-name"], str(group.GroupName))
		}
		for _, address := range d.PrivateIpAddresses {
			fields["addresses.private-ip-address"] = append(fields["addresses.private-ip-address"], str(address.PrivateIpAddress))
			fields["addresses.primary"] = append(fields["addresses.primary"], strconv.FormatBool(boolValue(address.Primary)))
			if address.PrivateDnsName != nil {
				fields["addresses.private-dns-name"] = append(fields["addresses.private-dns-name"], str(address.PrivateDnsName))
			}
			if a := address.Association; a != nil {
				fields["addresses.association.public-ip"] = append(fields["addresses.association.public-ip"], str(a.PublicIp))
				fields["addresses.association.ip-owner-id"] = append(fields["addresses.association.ip-owner-id"], str(a.IpOwnerId))
			}
		}
		if a := d.Association; a != nil {
			fields["association.public-ip"] = []string{str(a.PublicIp)}
			fields["association.allocation-id"] = []string{str(a.AllocationId)}
			fields["association.association-id"] = []string{str(a.AssociationId)}
			fields["association.ip-owner-id"] = []string{str(a.IpOwnerId)}
			fields["association.public-dns-name"] = []string{str(a.PublicDnsName)}
		}
		items = append(items, pageItem{ID: record.Key.ID, Tags: d.TagSet, Fields: fields})
		d.Operator = &api.OperatorResponse{Managed: new(api.Boolean(false)), HiddenByDefault: new(api.Boolean(false))}
		byID[record.Key.ID] = d
	}
	ids, next, err := selectPage(ctx, "DescribeNetworkInterfaces", stringsOf(in.NetworkInterfaceIds), in.Filters, maxResults(in.MaxResults), in.NextToken, items)
	if err != nil {
		return nil, err
	}
	out := &api.DescribeNetworkInterfacesResult{NetworkInterfaces: api.NetworkInterfaceList{}, NextToken: next}
	for _, id := range ids {
		out.NetworkInterfaces = append(out.NetworkInterfaces, byID[id])
	}
	return out, nil
}

func (s *Service) deleteNetworkInterface(ctx context.Context, tx Transaction, in *api.DeleteNetworkInterfaceRequest) (*emptyResult, error) {
	id := str(in.NetworkInterfaceId)
	record, err := s.authorizeNetworkInterface(ctx, tx, "DeleteNetworkInterface", id)
	if err != nil {
		return nil, err
	}
	if err := dryRun(in.DryRun); err != nil {
		return nil, err
	}
	if err := requireNetworkInterface(record, id); err != nil {
		return nil, err
	}
	if record.Data.Attachment != nil || str(record.Data.Status) == "in-use" {
		return nil, failure("InvalidParameterValue", "Network interface '"+id+"' is currently in use.")
	}
	if err := ownedUnattachedNetworkInterface(record); err != nil {
		return nil, err
	}
	subnet, err := interfaceSubnet(tx, record)
	if err != nil {
		return nil, err
	}
	if err := changeNetworkInterfaceCapacity(tx, subnet, len(record.Data.PrivateIpAddresses)); err != nil {
		return nil, err
	}
	if err := releaseInterfacePublicAddresses(ctx, tx, id, true); err != nil {
		return nil, err
	}
	if err := tx.DeleteNetworkInterface(record.Key); err != nil {
		return nil, err
	}
	// Creation records deliberately survive deletion: retries cannot resurrect it.
	return &emptyResult{}, nil
}

func ownedUnattachedNetworkInterface(record NetworkInterfaceRecord) error {
	if boolValue(record.Data.RequesterManaged) || (record.Data.Operator != nil && boolValue(record.Data.Operator.Managed)) {
		return failure("AuthFailure", "You do not have permission to access the specified resource.")
	}
	if record.Data.Attachment != nil {
		// TODO: Comeback implement customer instance attachment mutations.
		return unsupported("Attached network interface mutation is not implemented.")
	}
	return nil
}
