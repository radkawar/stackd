package ec2

import (
	"context"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"stackd/compute/network"
	api "stackd/internal/awsapi/ec2"
)

func networkSpecification(ctx context.Context, tx Reader, eni NetworkInterfaceRecord) (network.Specification, error) {
	var out network.Specification
	subnet, err := interfaceSubnet(tx, eni)
	if err != nil {
		return out, err
	}
	vpc, err := tx.VPC(ResourceKey{Scope: subnet.Key.Scope, ID: str(eni.Data.VpcId)})
	if err != nil {
		return out, err
	}
	out.NetworkID = resourceARN(vpc.Key.Scope, "vpc", vpc.Key.ID)
	out.Pool, err = taskIPv4Prefix(str(vpc.Data.CidrBlock))
	if err != nil {
		return out, err
	}
	out.Gateway = out.Pool.Addr().Next()
	out.Address, err = netip.ParseAddr(str(eni.Data.PrivateIpAddress))
	if err != nil {
		return out, err
	}
	out.MAC = str(eni.Data.MacAddress)
	out.Policy.Subnet, err = taskIPv4Prefix(str(subnet.Data.CidrBlock))
	if err != nil {
		return out, err
	}
	out.DNSSupport = vpc.DNSSupport
	out.Hostname = privateDNSName(scopeFor(ctx), out.Address.String())
	if id := str(vpc.Data.DhcpOptionsId); id != "" && id != "default" {
		options, err := tx.DHCPOptions(ResourceKey{Scope: vpc.Key.Scope, ID: id})
		if err != nil {
			return out, err
		}
		for _, option := range options.Data.DhcpConfigurations {
			switch str(option.Key) {
			case "domain-name":
				values := make([]string, 0, len(option.Values))
				for _, value := range option.Values {
					values = append(values, str(value.Value))
				}
				out.DomainName = strings.Join(values, " ")
			case "domain-name-servers":
				for _, value := range option.Values {
					address := str(value.Value)
					if address == "AmazonProvidedDNS" {
						out.DNS = append(out.DNS, out.Pool.Addr().Next().Next())
						continue
					}
					server, err := netip.ParseAddr(address)
					if err != nil || !server.Is4() {
						return out, unsupported("Native compute DHCP currently requires IPv4 DNS servers.")
					}
					out.DNS = append(out.DNS, server)
				}
			case "ntp-servers", "netbios-name-servers":
				for _, value := range option.Values {
					server, err := netip.ParseAddr(str(value.Value))
					if err != nil || !server.Is4() {
						return out, unsupported("Native compute DHCP currently requires IPv4 option servers.")
					}
					if str(option.Key) == "ntp-servers" {
						out.NTPServers = append(out.NTPServers, server)
					} else {
						out.NetBIOSServers = append(out.NetBIOSServers, server)
					}
				}
			case "netbios-node-type":
				if len(option.Values) > 0 {
					out.NetBIOSNodeType, err = strconv.Atoi(str(option.Values[0].Value))
					if err != nil {
						return out, err
					}
				}
			}
		}
	}
	peers, err := tx.RegionalNetworkInterfaces(eni.Key.Scope)
	if err != nil {
		return out, err
	}
	for _, membership := range eni.Data.Groups {
		group, err := tx.SecurityGroup(ResourceKey{Scope: eni.Key.Scope, ID: str(membership.GroupId)})
		if err != nil {
			return out, err
		}
		ingress, err := taskSecurityRules(group.Data.IpPermissions, peers, eni)
		if err != nil {
			return out, err
		}
		egress, err := taskSecurityRules(group.Data.IpPermissionsEgress, peers, eni)
		if err != nil {
			return out, err
		}
		out.Policy.SecurityIngress = append(out.Policy.SecurityIngress, ingress...)
		out.Policy.SecurityEgress = append(out.Policy.SecurityEgress, egress...)
	}
	acls, err := tx.NetworkACLs(subnet.Key.Scope)
	if err != nil {
		return out, err
	}
	for _, acl := range acls {
		if str(acl.Data.VpcId) != vpc.Key.ID {
			continue
		}
		associated := false
		for _, association := range acl.Data.Associations {
			if str(association.SubnetId) == subnet.Key.ID {
				associated = true
				break
			}
		}
		if !associated {
			continue
		}
		for _, entry := range acl.Data.Entries {
			if entry.CidrBlock == nil {
				continue
			}
			rule, err := taskIPRule(str(entry.Protocol), nil, nil)
			if err != nil {
				return out, err
			}
			rule.CIDR, err = taskIPv4Prefix(str(entry.CidrBlock))
			if err != nil {
				return out, err
			}
			if entry.PortRange != nil {
				rule.FromPort, rule.ToPort = taskInt(entry.PortRange.From, 0), taskInt(entry.PortRange.To, 65535)
			}
			if entry.IcmpTypeCode != nil {
				rule.ICMPType, rule.ICMPCode = taskInt(entry.IcmpTypeCode.Type, -1), taskInt(entry.IcmpTypeCode.Code, -1)
			}
			normalized := network.ACLRule{Rule: rule, Number: taskInt(entry.RuleNumber, 32767), Allow: str(entry.RuleAction) == "allow"}
			if boolValue(entry.Egress) {
				out.Policy.ACLEgress = append(out.Policy.ACLEgress, normalized)
			} else {
				out.Policy.ACLIngress = append(out.Policy.ACLIngress, normalized)
			}
		}
		break
	}
	slices.SortFunc(out.Policy.ACLIngress, func(a, b network.ACLRule) int { return a.Number - b.Number })
	slices.SortFunc(out.Policy.ACLEgress, func(a, b network.ACLRule) int { return a.Number - b.Number })
	projected, err := networkInterfaceProjection(ctx, tx, eni)
	if err != nil {
		return out, err
	}
	if projected.Association != nil {
		out.Policy.PublicIPv4, err = netip.ParseAddr(str(projected.Association.PublicIp))
		if err != nil {
			return out, err
		}
		out.PublicHostname = str(projected.Association.PublicDnsName)
		out.Policy.PublicEgress, err = taskInternetRoute(ctx, tx, subnet)
		if err != nil {
			return out, err
		}
	}
	// TODO: Comeback implement IPv6 DHCP and non-local routing targets.
	return out, nil
}

func taskIPv4Prefix(value string) (netip.Prefix, error) {
	prefix, err := netip.ParsePrefix(value)
	if err != nil || !prefix.Addr().Is4() {
		return netip.Prefix{}, unsupported("Task networks require actual IPv4 VPC and subnet CIDRs.")
	}
	return prefix.Masked(), nil
}

func taskInt(value *api.Integer, fallback int) int {
	if value == nil {
		return fallback
	}
	return int(*value)
}

func taskIPRule(protocol string, from, to *api.Integer) (network.IPRule, error) {
	rule := network.IPRule{FromPort: 0, ToPort: 65535, ICMPType: -1, ICMPCode: -1}
	switch protocol {
	case "tcp":
		rule.Protocol = 6
	case "udp":
		rule.Protocol = 17
	case "icmp":
		rule.Protocol = 1
	default:
		var err error
		rule.Protocol, err = strconv.Atoi(protocol)
		if err != nil || rule.Protocol < -1 || rule.Protocol > 255 {
			return rule, fmt.Errorf("ec2: invalid retained IP protocol %q", protocol)
		}
	}
	if rule.Protocol == 6 || rule.Protocol == 17 {
		rule.FromPort, rule.ToPort = taskInt(from, 0), taskInt(to, 65535)
	}
	if rule.Protocol == 1 {
		rule.ICMPType, rule.ICMPCode = taskInt(from, -1), taskInt(to, -1)
	}
	return rule, nil
}

func taskSecurityRules(permissions api.IpPermissionList, peers []NetworkInterfaceRecord, eni NetworkInterfaceRecord) ([]network.IPRule, error) {
	var out []network.IPRule
	for _, permission := range permissions {
		rule, err := taskIPRule(str(permission.IpProtocol), permission.FromPort, permission.ToPort)
		if err != nil {
			return nil, err
		}
		if len(permission.PrefixListIds) != 0 {
			return nil, unsupported("Task security-group prefix-list references require a native prefix-list resolver.")
		}
		for _, cidr := range permission.IpRanges {
			rule.CIDR, err = taskIPv4Prefix(str(cidr.CidrIp))
			if err != nil {
				return nil, err
			}
			out = append(out, rule)
		}
		for _, reference := range permission.UserIdGroupPairs {
			for _, peer := range peers {
				if str(peer.Data.VpcId) != str(eni.Data.VpcId) || interfaceSubnetKey(peer).Scope != interfaceSubnetKey(eni).Scope {
					continue
				}
				if reference.UserId != nil && str(reference.UserId) != peer.Key.Scope.AccountID {
					continue
				}
				if reference.VpcId != nil && str(reference.VpcId) != str(peer.Data.VpcId) {
					continue
				}
				matches := false
				for _, group := range peer.Data.Groups {
					if str(group.GroupId) == str(reference.GroupId) {
						matches = true
						break
					}
				}
				if !matches {
					continue
				}
				for _, address := range peer.Data.PrivateIpAddresses {
					ip, err := netip.ParseAddr(str(address.PrivateIpAddress))
					if err != nil {
						return nil, err
					}
					if !ip.Is4() {
						continue
					}
					rule.CIDR = netip.PrefixFrom(ip, 32)
					out = append(out, rule)
				}
			}
		}
	}
	return out, nil
}

func taskInternetRoute(ctx context.Context, tx Reader, subnet SubnetRecord) (bool, error) {
	tables, err := tx.RouteTables(subnet.Key.Scope)
	if err != nil {
		return false, err
	}
	var selected, main *RouteTableRecord
	for i := range tables {
		table := &tables[i]
		if str(table.Data.VpcId) != str(subnet.Data.VpcId) {
			continue
		}
		for _, association := range table.Data.Associations {
			if association.AssociationState != nil && str(association.AssociationState.State) != "associated" {
				continue
			}
			if str(association.SubnetId) == subnet.Key.ID {
				selected = table
			}
			if boolValue(association.Main) {
				main = table
			}
		}
	}
	if selected == nil {
		selected = main
	}
	if selected == nil {
		return false, nil
	}
	for _, route := range selected.Data.Routes {
		if str(route.DestinationCidrBlock) != "0.0.0.0/0" || str(route.State) != "active" {
			continue
		}
		gateway, err := tx.InternetGateway(ResourceKey{Scope: subnet.Key.Scope, ID: str(route.GatewayId)})
		if err == ErrNotFound {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		for _, attachment := range gateway.Data.Attachments {
			if str(attachment.VpcId) == str(subnet.Data.VpcId) && str(attachment.State) == "available" {
				return true, nil
			}
		}
	}
	return false, nil
}
