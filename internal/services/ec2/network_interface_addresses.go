package ec2

import (
	"context"
	"encoding/binary"
	"fmt"
	"net/netip"
	"slices"
	"strings"

	api "stackd/internal/awsapi/ec2"
)

type networkInterfaceAddressOwner struct {
	id      string
	primary bool
}

type networkInterfaceIPv4Pool struct {
	prefix            netip.Prefix
	first, last, next uint32
	used              map[string]networkInterfaceAddressOwner
	records           map[string]NetworkInterfaceRecord
}

func networkInterfaceAddressPool(ctx context.Context, tx Reader, subnet SubnetRecord) (*networkInterfaceIPv4Pool, error) {
	prefix, err := netip.ParsePrefix(str(subnet.Data.CidrBlock))
	if err != nil || !prefix.Addr().Is4() {
		// TODO: Comeback implement IPv6 subnet address allocation.
		return nil, unsupported("IPv6-only network interface allocation is not implemented.")
	}
	prefix = prefix.Masked()
	bytes := prefix.Addr().As4()
	base := binary.BigEndian.Uint32(bytes[:])
	pool := &networkInterfaceIPv4Pool{prefix: prefix, first: base + 4, last: base | uint32((uint64(1)<<uint(32-prefix.Bits()))-1), next: base + 4, used: map[string]networkInterfaceAddressOwner{}, records: map[string]NetworkInterfaceRecord{}}
	records, err := tx.RegionalNetworkInterfaces(subnet.Key.Scope)
	if err != nil {
		return nil, err
	}
	for _, record := range records {
		if interfaceSubnetKey(record) != subnet.Key {
			continue
		}
		pool.records[record.Key.ID] = record
		for _, address := range record.Data.PrivateIpAddresses {
			pool.used[str(address.PrivateIpAddress)] = networkInterfaceAddressOwner{id: record.Key.ID, primary: boolValue(address.Primary)}
		}
	}
	return pool, nil
}

func (p *networkInterfaceIPv4Pool) validate(ip string, assigning bool) error {
	address, err := netip.ParseAddr(ip)
	if err != nil || !address.Is4() {
		return failure("InvalidParameterValue", "invalid value for parameter address: "+ip)
	}
	if !p.prefix.Contains(address) {
		return failure("InvalidParameterValue", "Address does not fall within the subnet's address range")
	}
	bytes := address.As4()
	number := binary.BigEndian.Uint32(bytes[:])
	if number < p.first || number >= p.last {
		message := "Address is in subnet's reserved address range"
		if assigning {
			message = "Address " + ip + " is in subnet's reserved range."
		}
		return failure("InvalidParameterValue", message)
	}
	return nil
}

func (p *networkInterfaceIPv4Pool) reserveExplicit(ip string, assigning bool) error {
	if err := p.validate(ip, assigning); err != nil {
		return err
	}
	if _, occupied := p.used[ip]; occupied {
		return failure("InvalidIPAddress.InUse", "The specified address is already in use.")
	}
	p.used[ip] = networkInterfaceAddressOwner{}
	return nil
}

func (p *networkInterfaceIPv4Pool) allocate() (string, error) {
	for p.next < p.last {
		var bytes [4]byte
		binary.BigEndian.PutUint32(bytes[:], p.next)
		p.next++
		ip := netip.AddrFrom4(bytes).String()
		if _, occupied := p.used[ip]; occupied {
			continue
		}
		p.used[ip] = networkInterfaceAddressOwner{}
		return ip, nil
	}
	return "", failure("InsufficientFreeAddressesInSubnet", "The specified subnet does not have enough free addresses to satisfy the request.")
}

func newNetworkInterfaceAddress(ip string, primary bool) api.NetworkInterfacePrivateIpAddress {
	address := api.NetworkInterfacePrivateIpAddress{PrivateIpAddress: new(api.String(ip)), Primary: new(api.Boolean(primary))}
	if !primary {
		address.PrivateDnsName = new(api.String(""))
	}
	return address
}

func validateSecondaryAddressCount(count *api.Integer) error {
	if count != nil && *count <= 0 {
		return failure("InvalidParameterValue", fmt.Sprintf("Value (%d) for parameter secondaryPrivateIpAddressCount is invalid. Value must be a positive number.", *count))
	}
	return nil
}

func changeNetworkInterfaceCapacity(tx Transaction, subnet SubnetRecord, delta int) error {
	// Allocation owns exhaustion checks; committed address changes own the count.
	// A participant-facing projection must never overwrite owner tags or AZ
	// names when consuming capacity from the canonical shared subnet.
	current, err := tx.Subnet(subnet.Key)
	if err != nil {
		return err
	}
	subnet = current
	*subnet.Data.AvailableIpAddressCount += api.Integer(delta)
	return tx.PutSubnet(subnet)
}

func (s *Service) assignPrivateIpAddresses(ctx context.Context, tx Transaction, in *api.AssignPrivateIpAddressesRequest) (*api.AssignPrivateIpAddressesResult, error) {
	id := str(in.NetworkInterfaceId)
	record, err := s.authorizeNetworkInterface(ctx, tx, "AssignPrivateIpAddresses", id)
	if err != nil {
		return nil, err
	}
	if err := requireNetworkInterface(record, id); err != nil {
		return nil, err
	}
	if err := ownedUnattachedNetworkInterface(record); err != nil {
		return nil, err
	}
	if in.Ipv4PrefixCount != nil || len(in.Ipv4Prefixes) > 0 {
		// TODO: Comeback implement delegated IPv4 prefix allocation and overlap tracking.
		return nil, unsupported("Delegated IPv4 prefix allocation is not implemented.")
	}
	if len(in.PrivateIpAddresses) == 0 && in.SecondaryPrivateIpAddressCount == nil {
		return nil, failure("InvalidParameter", "One of privateIpAddressSet or privateIpAddressCount or ipv4PrefixSet or ipv4PrefixCount must be specified.")
	}
	if len(in.PrivateIpAddresses) > 0 && in.SecondaryPrivateIpAddressCount != nil {
		return nil, failure("InvalidParameterCombination", "You may specify one and only one of privateIpAddressSet or secondaryPrivateIpAddressCount or ipv4Prefixes or ipv4PrefixCount, but not more than one of them.")
	}
	if err := validateSecondaryAddressCount(in.SecondaryPrivateIpAddressCount); err != nil {
		return nil, err
	}
	subnet, err := interfaceSubnet(tx, record)
	if err != nil {
		return nil, err
	}
	pool, err := networkInterfaceAddressPool(ctx, tx, subnet)
	if err != nil {
		return nil, err
	}
	requested := stringsOf(in.PrivateIpAddresses)
	if in.SecondaryPrivateIpAddressCount != nil {
		for range int(*in.SecondaryPrivateIpAddressCount) {
			ip, err := pool.allocate()
			if err != nil {
				return nil, err
			}
			requested = append(requested, ip)
		}
	}
	seen := make(map[string]bool, len(requested))
	changed := map[string]NetworkInterfaceRecord{}
	movesDenied := []string{}
	allocated := 0
	out := &api.AssignPrivateIpAddressesResult{NetworkInterfaceId: new(api.String(id)), AssignedPrivateIpAddresses: api.AssignedPrivateIpAddressList{}, AssignedIpv4Prefixes: api.Ipv4PrefixesList{}}
	for _, ip := range requested {
		if seen[ip] {
			continue
		}
		seen[ip] = true
		if err := pool.validate(ip, true); err != nil {
			return nil, err
		}
		owner := pool.used[ip]
		if owner.id != "" && owner.id != id {
			source, ok := changed[owner.id]
			if !ok {
				source = pool.records[owner.id]
				if source.Key.Scope != record.Key.Scope {
					return nil, failure("InvalidIPAddress.InUse", "The specified address belongs to another account.")
				}
				// Reassignment mutates the old ENI too. Never let destination-only
				// permission move an address away from an unauthorized source.
				if err := s.authorize(ctx, "AssignPrivateIpAddresses", "network-interface", source.Key.ID, source.Data.TagSet); err != nil {
					return nil, err
				}
				if err := ownedUnattachedNetworkInterface(source); err != nil {
					return nil, err
				}
			}
			if owner.primary {
				return nil, failure("InvalidParameterValue", "secondary-addresses")
			}
			if !boolValue(in.AllowReassignment) {
				movesDenied = append(movesDenied, ip)
				continue
			}
			source.Data.PrivateIpAddresses = slices.DeleteFunc(source.Data.PrivateIpAddresses, func(address api.NetworkInterfacePrivateIpAddress) bool { return str(address.PrivateIpAddress) == ip })
			changed[owner.id] = source
			addresses, err := tx.PublicAddresses(scopeFor(ctx))
			if err != nil {
				return nil, err
			}
			for _, address := range addresses {
				if str(address.Data.NetworkInterfaceId) == source.Key.ID && str(address.Data.PrivateIpAddress) == ip {
					address.Data.NetworkInterfaceId = new(api.String(id))
					if err := tx.PutPublicAddress(address); err != nil {
						return nil, err
					}
				}
			}
		}
		if owner.id != id {
			record.Data.PrivateIpAddresses = append(record.Data.PrivateIpAddresses, newNetworkInterfaceAddress(ip, false))
			if owner.id == "" {
				allocated++
			}
		}
		out.AssignedPrivateIpAddresses = append(out.AssignedPrivateIpAddresses, api.AssignedPrivateIpAddress{PrivateIpAddress: new(api.String(ip))})
	}
	if len(movesDenied) > 0 {
		return nil, failure("InvalidParameterValue", "["+strings.Join(movesDenied, ", ")+"] assigned, but move is not allowed.")
	}
	for _, source := range changed {
		if err := tx.PutNetworkInterface(source); err != nil {
			return nil, err
		}
	}
	if err := tx.PutNetworkInterface(record); err != nil {
		return nil, err
	}
	if allocated > 0 {
		if err := changeNetworkInterfaceCapacity(tx, subnet, -allocated); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func (s *Service) unassignPrivateIpAddresses(ctx context.Context, tx Transaction, in *api.UnassignPrivateIpAddressesRequest) (*emptyResult, error) {
	id := str(in.NetworkInterfaceId)
	record, err := s.authorizeNetworkInterface(ctx, tx, "UnassignPrivateIpAddresses", id)
	if err != nil {
		return nil, err
	}
	if err := requireNetworkInterface(record, id); err != nil {
		return nil, err
	}
	if err := ownedUnattachedNetworkInterface(record); err != nil {
		return nil, err
	}
	if len(in.Ipv4Prefixes) > 0 {
		// TODO: Comeback release delegated IPv4 prefixes through their allocation state.
		return nil, unsupported("Delegated IPv4 prefix release is not implemented.")
	}
	if len(in.PrivateIpAddresses) == 0 {
		return nil, failure("MissingParameter", "One of privateIpAddresses or ipv4Prefixes must be specified.")
	}
	remove := make(map[string]bool, len(in.PrivateIpAddresses))
	for _, rawIP := range in.PrivateIpAddresses {
		ip := string(rawIP)
		found := false
		for _, address := range record.Data.PrivateIpAddresses {
			if str(address.PrivateIpAddress) != ip {
				continue
			}
			found = true
			if boolValue(address.Primary) {
				return nil, failure("InvalidParameterValue", "Value ("+ip+") for parameter privateIpAddress is invalid. The primary IP address of an interface cannot be unassigned.")
			}
			break
		}
		if !found {
			return nil, failure("InvalidParameterValue", "Some of the specified addresses are not assigned to interface "+id)
		}
		remove[ip] = true
	}
	addresses, err := tx.PublicAddresses(scopeFor(ctx))
	if err != nil {
		return nil, err
	}
	for _, address := range addresses {
		if str(address.Data.NetworkInterfaceId) == id && remove[str(address.Data.PrivateIpAddress)] {
			clearAddressAssociation(&address)
			if err := tx.PutPublicAddress(address); err != nil {
				return nil, err
			}
		}
	}
	record.Data.PrivateIpAddresses = slices.DeleteFunc(record.Data.PrivateIpAddresses, func(address api.NetworkInterfacePrivateIpAddress) bool { return remove[str(address.PrivateIpAddress)] })
	subnet, err := interfaceSubnet(tx, record)
	if err != nil {
		return nil, err
	}
	if err := tx.PutNetworkInterface(record); err != nil {
		return nil, err
	}
	if err := changeNetworkInterfaceCapacity(tx, subnet, len(remove)); err != nil {
		return nil, err
	}
	return &emptyResult{}, nil
}
