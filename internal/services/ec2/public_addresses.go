package ec2

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"net/netip"
	"strings"

	api "stackd/internal/awsapi/ec2"
)

func registerPublicAddresses(s *Service) {
	register(s, "AllocateAddress", s.allocateAddress)
	register(s, "DescribeAddresses", s.describeAddresses)
	register(s, "AssociateAddress", s.associateAddress)
	register(s, "DisassociateAddress", s.disassociateAddress)
	register(s, "ReleaseAddress", s.releaseAddress)
}

// The benchmark pool is deliberately not Internet-advertised. Native mappings
// make these addresses reachable on the controller host; upstream egress uses
// that host's real public path. EC2 alone reserves addresses across all scopes.
func allocatePublicIPv4(tx Transaction, scope Scope) (string, error) {
	used, err := tx.PublicIPv4Reservations()
	if err != nil {
		return "", err
	}
	reserved := make(map[string]bool, len(used))
	for _, ip := range used {
		reserved[ip] = true
	}
	nonce, err := tx.NextID(scope, "public-ip")
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(nonce))
	const size = 1 << 17
	start := binary.BigEndian.Uint32(sum[:4])%(size-2) + 1
	for offset := uint32(0); offset < size-2; offset++ {
		n := (start-1+offset)%(size-2) + 1
		ip := netip.AddrFrom4([4]byte{198, 18 + byte(n>>16), byte(n >> 8), byte(n)}).String()
		if !reserved[ip] {
			return ip, nil
		}
	}
	return "", failure("InsufficientAddressCapacity", "The local public IPv4 pool is exhausted.")
}

func (s *Service) allocateAddress(ctx context.Context, tx Transaction, in *api.AllocateAddressRequest) (*api.AllocateAddressResult, error) {
	if err := validatePublicIPv4(str(in.Address)); err != nil {
		return nil, err
	}
	if in.NetworkBorderGroup != nil && str(in.NetworkBorderGroup) != scopeFor(ctx).Region {
		return nil, failure("InvalidParameterValue", "Invalid network border group.")
	}
	tags, err := CreationTags(in.TagSpecifications, "elastic-ip")
	if err != nil {
		return nil, err
	}
	if err := s.authorizeCreate(ctx, "AllocateAddress", "elastic-ip", "*", tags); err != nil {
		return nil, err
	}
	if err := dryRun(in.DryRun); err != nil {
		return nil, err
	}
	if in.Domain != nil && str(in.Domain) != "vpc" {
		return nil, failure("InvalidParameterValue", "Only the vpc domain is supported.")
	}
	if in.Address != nil || in.CustomerOwnedIpv4Pool != nil || in.IpamPoolId != nil || (in.PublicIpv4Pool != nil && str(in.PublicIpv4Pool) != "amazon") {
		// TODO: Comeback implement public IPv4 recovery, BYOIP, customer pools and IPAM through their real pool owners.
		return nil, unsupported("Only new Amazon-pool VPC Elastic IP allocations are implemented.")
	}
	border := scopeFor(ctx).Region
	rows, err := tx.PublicAddresses(scopeFor(ctx))
	if err != nil {
		return nil, err
	}
	count := 0
	for _, row := range rows {
		if !row.Automatic {
			count++
		}
	}
	if count >= 5 {
		return nil, failure("AddressLimitExceeded", "The maximum number of addresses has been reached.")
	}
	id, err := tx.NextID(scopeFor(ctx), "eipalloc")
	if err != nil {
		return nil, err
	}
	ip, err := allocatePublicIPv4(tx, scopeFor(ctx))
	if err != nil {
		return nil, err
	}
	d := api.Address{AllocationId: new(api.String(id)), PublicIp: new(api.String(ip)), Domain: new(api.DomainType("vpc")), PublicIpv4Pool: new(api.String("amazon")), NetworkBorderGroup: new(api.String(border)), Tags: tags}
	if err := tx.PutPublicAddress(PublicAddressRecord{Key: key(ctx, id), Data: d}); err != nil {
		return nil, err
	}
	return &api.AllocateAddressResult{AllocationId: d.AllocationId, PublicIp: d.PublicIp, Domain: d.Domain, PublicIpv4Pool: d.PublicIpv4Pool, NetworkBorderGroup: d.NetworkBorderGroup}, nil
}

func publicAddressMissing(id, ip string) error {
	if id != "" {
		return failure("InvalidAllocationID.NotFound", "The allocation ID '"+id+"' does not exist")
	}
	return failure("InvalidAddress.NotFound", "The address '"+ip+"' does not exist")
}
func loadPublicAddress(ctx context.Context, tx Reader, id, ip string) (PublicAddressRecord, error) {
	var out PublicAddressRecord
	if id == "" && ip == "" {
		return out, failure("MissingParameter", "The request must contain the parameter AllocationId")
	}
	if id != "" {
		out, err := tx.PublicAddress(key(ctx, id))
		if errors.Is(err, ErrNotFound) || err == nil && out.Automatic {
			return out, publicAddressMissing(id, ip)
		}
		return out, err
	}
	rows, err := tx.PublicAddresses(scopeFor(ctx))
	if err != nil {
		return out, err
	}
	for _, row := range rows {
		if !row.Automatic && str(row.Data.PublicIp) == ip {
			return row, nil
		}
	}
	return out, publicAddressMissing(id, ip)
}

func addressProjection(ctx context.Context, tx Reader, row PublicAddressRecord) (api.Address, error) {
	d := row.Data
	if id := str(d.NetworkInterfaceId); id != "" {
		eni, err := tx.NetworkInterface(key(ctx, id))
		if err != nil {
			return d, err
		}
		d.NetworkInterfaceOwnerId = new(api.String(eni.Key.Scope.AccountID))
		if eni.Data.Attachment != nil {
			d.InstanceId = eni.Data.Attachment.InstanceId
		}
	}
	return d, nil
}
func (s *Service) describeAddresses(ctx context.Context, tx Transaction, in *api.DescribeAddressesRequest) (*api.DescribeAddressesResult, error) {
	for _, ip := range in.PublicIps {
		if err := validatePublicIPv4(string(ip)); err != nil {
			return nil, err
		}
	}
	if err := s.authorize(ctx, "DescribeAddresses", "", "*", nil); err != nil {
		return nil, err
	}
	if err := dryRun(in.DryRun); err != nil {
		return nil, err
	}
	rows, err := tx.PublicAddresses(scopeFor(ctx))
	if err != nil {
		return nil, err
	}
	selected := map[string]bool{}
	for _, id := range in.AllocationIds {
		row, err := loadPublicAddress(ctx, tx, string(id), "")
		if err != nil {
			return nil, err
		}
		selected[row.Key.ID] = true
	}
	for _, ip := range in.PublicIps {
		row, err := loadPublicAddress(ctx, tx, "", string(ip))
		if err != nil {
			return nil, err
		}
		selected[row.Key.ID] = true
	}
	var items []pageItem
	data := map[string]api.Address{}
	for _, row := range rows {
		if row.Automatic || len(selected) > 0 && !selected[row.Key.ID] {
			continue
		}
		d, err := addressProjection(ctx, tx, row)
		if err != nil {
			return nil, err
		}
		data[row.Key.ID] = d
		items = append(items, pageItem{ID: row.Key.ID, Tags: d.Tags, Fields: map[string][]string{"allocation-id": {row.Key.ID}, "association-id": {str(d.AssociationId)}, "domain": {str(d.Domain)}, "instance-id": {str(d.InstanceId)}, "network-interface-id": {str(d.NetworkInterfaceId)}, "network-interface-owner-id": {str(d.NetworkInterfaceOwnerId)}, "private-ip-address": {str(d.PrivateIpAddress)}, "public-ip": {str(d.PublicIp)}, "public-ipv4-pool": {str(d.PublicIpv4Pool)}, "network-border-group": {str(d.NetworkBorderGroup)}}})
	}
	ids, _, err := selectPage(ctx, "DescribeAddresses", nil, in.Filters, nil, nil, items)
	if err != nil {
		return nil, err
	}
	out := &api.DescribeAddressesResult{Addresses: api.AddressList{}}
	for _, id := range ids {
		out.Addresses = append(out.Addresses, data[id])
	}
	return out, nil
}

func addressConditions(d api.Address) map[string][]string {
	conditions := make(map[string][]string, 3)
	if d.Domain != nil {
		conditions["ec2:Domain"] = []string{str(d.Domain)}
	}
	if d.AllocationId != nil {
		conditions["ec2:AllocationId"] = []string{str(d.AllocationId)}
	}
	if d.PublicIp != nil {
		conditions["ec2:PublicIpAddress"] = []string{str(d.PublicIp)}
	}
	return conditions
}
func (s *Service) associateAddress(ctx context.Context, tx Transaction, in *api.AssociateAddressRequest) (*api.AssociateAddressResult, error) {
	if boolValue(in.DryRun) {
		return nil, s.dryRunPublicAddress(ctx, tx, "AssociateAddress", str(in.AllocationId), str(in.PublicIp), "", str(in.NetworkInterfaceId), str(in.InstanceId))
	}
	if in.AllocationId != nil && in.PublicIp != nil {
		return nil, failure("InvalidParameterCombination", "You may specify public IP or allocation id, but not both in the same call")
	}
	if in.AllocationId == nil && in.PublicIp != nil && in.NetworkInterfaceId != nil {
		return nil, failure("InvalidParameterCombination", "You must specify an allocation id when mapping an address to a network interface")
	}
	if in.InstanceId != nil {
		if err := validateInstanceID(str(in.InstanceId)); err != nil {
			return nil, err
		}
	}
	row, err := loadPublicAddress(ctx, tx, str(in.AllocationId), str(in.PublicIp))
	if err != nil {
		return nil, err
	}
	if err := s.authorizeWith(ctx, "AssociateAddress", "elastic-ip", row.Key.ID, row.Data.Tags, addressConditions(row.Data)); err != nil {
		return nil, err
	}
	if in.InstanceId != nil && in.NetworkInterfaceId != nil {
		return nil, failure("InvalidParameterCombination", "Specify either InstanceId or NetworkInterfaceId, but not both.")
	}
	eniID := str(in.NetworkInterfaceId)
	if instanceID := str(in.InstanceId); instanceID != "" {
		instance, err := tx.Instance(key(ctx, instanceID))
		if errors.Is(err, ErrNotFound) {
			return nil, missing("instance", instanceID)
		}
		if err != nil {
			return nil, err
		}
		if err := s.authorizeWith(ctx, "AssociateAddress", "instance", instanceID, instance.Data.Tags, instanceProfileConditions(instance)); err != nil {
			return nil, err
		}
		if len(instance.Data.NetworkInterfaces) != 1 {
			return nil, failure("InvalidInstanceID", "The instance must have exactly one network interface.")
		}
		eniID = str(instance.Data.NetworkInterfaces[0].NetworkInterfaceId)
	}
	if eniID == "" {
		return nil, failure("MissingParameter", "The request must contain either InstanceId or NetworkInterfaceId")
	}
	eni, err := tx.NetworkInterface(key(ctx, eniID))
	if errors.Is(err, ErrNotFound) {
		return nil, missing("network-interface", eniID)
	}
	if err != nil {
		return nil, err
	}
	if err := s.authorizeWith(ctx, "AssociateAddress", "network-interface", eniID, eni.Data.TagSet, addressInterfaceConditions(scopeFor(ctx), eniID, eni)); err != nil {
		return nil, err
	}
	if err := dryRun(in.DryRun); err != nil {
		return nil, err
	}
	if boolValue(eni.Data.RequesterManaged) {
		return nil, failure("AuthFailure", "You do not have permission to access the specified resource.")
	}
	ip := str(in.PrivateIpAddress)
	if ip == "" {
		ip = str(eni.Data.PrivateIpAddress)
	}
	found := false
	for _, private := range eni.Data.PrivateIpAddresses {
		found = found || str(private.PrivateIpAddress) == ip
	}
	if !found {
		return nil, failure("InvalidParameterValue", "The specified private IP address does not belong to the network interface.")
	}
	if str(row.Data.NetworkBorderGroup) != scopeFor(ctx).Region {
		return nil, failure("InvalidAddress.NotFound", "The address and network interface have different network border groups.")
	}
	gateway, err := attachedInternetGateway(ctx, tx, str(eni.Data.VpcId))
	if err != nil {
		return nil, err
	}
	if !gateway {
		return nil, failure("Gateway.NotAttached", "The network interface's VPC has no attached Internet gateway.")
	}
	same := str(row.Data.NetworkInterfaceId) == eniID && str(row.Data.PrivateIpAddress) == ip
	if row.Data.AssociationId != nil && !same && in.AllowReassociation != nil && !boolValue(in.AllowReassociation) {
		return nil, failure("Resource.AlreadyAssociated", "The address is already associated.")
	}
	if same {
		return &api.AssociateAddressResult{AssociationId: row.Data.AssociationId}, nil
	}
	oldENI := str(row.Data.NetworkInterfaceId)
	rows, err := tx.PublicAddresses(scopeFor(ctx))
	if err != nil {
		return nil, err
	}
	for _, previous := range rows {
		if str(previous.Data.NetworkInterfaceId) != eniID || str(previous.Data.PrivateIpAddress) != ip {
			continue
		}
		if previous.Automatic {
			previous.Data.PublicIp = nil
		} else {
			clearAddressAssociation(&previous)
		}
		if err := tx.PutPublicAddress(previous); err != nil {
			return nil, err
		}
	}
	association, err := tx.NextID(scopeFor(ctx), "eipassoc")
	if err != nil {
		return nil, err
	}
	row.Data.AssociationId = new(api.String(association))
	row.Data.NetworkInterfaceId = new(api.String(eniID))
	row.Data.PrivateIpAddress = new(api.String(ip))
	if err := tx.PutPublicAddress(row); err != nil {
		return nil, err
	}
	if oldENI != "" {
		if err := restoreAutomaticPublicIPv4(ctx, tx, oldENI); err != nil {
			return nil, err
		}
	}
	if err := s.wakePublicNetwork(ctx, tx, oldENI, eniID); err != nil {
		return nil, err
	}
	return &api.AssociateAddressResult{AssociationId: row.Data.AssociationId}, nil
}
func clearAddressAssociation(row *PublicAddressRecord) {
	row.Data.AssociationId = nil
	row.Data.NetworkInterfaceId = nil
	row.Data.PrivateIpAddress = nil
}
func (s *Service) disassociateAddress(ctx context.Context, tx Transaction, in *api.DisassociateAddressRequest) (*emptyResult, error) {
	if boolValue(in.DryRun) {
		return nil, s.dryRunPublicAddress(ctx, tx, "DisassociateAddress", "", str(in.PublicIp), str(in.AssociationId), "", "")
	}
	if in.AssociationId == nil && in.PublicIp == nil {
		return nil, failure("MissingParameter", "Either public IP or association id must be specified")
	}
	rows, err := tx.PublicAddresses(scopeFor(ctx))
	if err != nil {
		return nil, err
	}
	var row PublicAddressRecord
	for _, candidate := range rows {
		if !candidate.Automatic && (in.AssociationId != nil && str(candidate.Data.AssociationId) == str(in.AssociationId) || in.AssociationId == nil && in.PublicIp != nil && str(candidate.Data.PublicIp) == str(in.PublicIp)) {
			row = candidate
			break
		}
	}
	if row.Key.ID == "" {
		return nil, failure("InvalidAssociationID.NotFound", "The association ID does not exist")
	}
	if err := s.authorizeWith(ctx, "DisassociateAddress", "elastic-ip", row.Key.ID, row.Data.Tags, addressConditions(row.Data)); err != nil {
		return nil, err
	}
	if err := dryRun(in.DryRun); err != nil {
		return nil, err
	}
	eniID := str(row.Data.NetworkInterfaceId)
	if eniID != "" {
		if err := s.authorizeAddressInterface(ctx, tx, "DisassociateAddress", eniID); err != nil {
			return nil, err
		}
	}
	clearAddressAssociation(&row)
	if err := tx.PutPublicAddress(row); err != nil {
		return nil, err
	}
	if err := restoreAutomaticPublicIPv4(ctx, tx, eniID); err != nil {
		return nil, err
	}
	if err := s.wakePublicNetwork(ctx, tx, eniID); err != nil {
		return nil, err
	}
	return &emptyResult{}, nil
}
func (s *Service) releaseAddress(ctx context.Context, tx Transaction, in *api.ReleaseAddressRequest) (*emptyResult, error) {
	if in.NetworkBorderGroup != nil && str(in.NetworkBorderGroup) != scopeFor(ctx).Region {
		if _, known := physicalAvailability.Regions[str(in.NetworkBorderGroup)]; !known {
			return nil, failure("InvalidParameterValue", "Invalid network border group.")
		}
	}
	if boolValue(in.DryRun) {
		return nil, s.dryRunPublicAddress(ctx, tx, "ReleaseAddress", str(in.AllocationId), str(in.PublicIp), "", "", "")
	}
	row, err := loadPublicAddress(ctx, tx, str(in.AllocationId), str(in.PublicIp))
	if err != nil {
		return nil, err
	}
	if err := s.authorizeWith(ctx, "ReleaseAddress", "elastic-ip", row.Key.ID, row.Data.Tags, addressConditions(row.Data)); err != nil {
		return nil, err
	}
	if err := dryRun(in.DryRun); err != nil {
		return nil, err
	}
	if in.NetworkBorderGroup != nil && str(in.NetworkBorderGroup) != str(row.Data.NetworkBorderGroup) {
		return nil, failure("InvalidAddress.NotFound", "The address is not in the specified network border group.")
	}
	if row.Data.AssociationId != nil {
		eni, err := tx.NetworkInterface(key(ctx, str(row.Data.NetworkInterfaceId)))
		if err != nil {
			return nil, err
		}
		vpc, err := tx.VPC(ResourceKey{Scope: interfaceSubnetKey(eni).Scope, ID: str(eni.Data.VpcId)})
		if err != nil {
			return nil, err
		}
		if !boolValue(vpc.Data.IsDefault) {
			return nil, failure("InvalidIPAddress.InUse", "The address is in use.")
		}
	}
	if err := tx.DeletePublicAddress(row.Key); err != nil {
		return nil, err
	}
	if eniID := str(row.Data.NetworkInterfaceId); eniID != "" {
		if err := restoreAutomaticPublicIPv4(ctx, tx, eniID); err != nil {
			return nil, err
		}
		if err := s.wakePublicNetwork(ctx, tx, eniID); err != nil {
			return nil, err
		}
	}
	return &emptyResult{}, nil
}

func publicDNSName(scope Scope, ip string) string {
	if ip == "" {
		return ""
	}
	suffix := scope.Region + ".compute.amazonaws.com"
	if scope.Region == "us-east-1" {
		suffix = "compute-1.amazonaws.com"
	}
	if scope.Partition == "aws-cn" {
		suffix += ".cn"
	}
	return "ec2-" + strings.ReplaceAll(ip, ".", "-") + "." + suffix
}
