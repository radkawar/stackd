package ec2

import (
	"context"
	"net/http"
	"slices"
	"strconv"
	"strings"
)

// Network metadata reads the current ENI/subnet/VPC/public-address projection.
// It does not invent IPv6 prefixes or additional network cards.
func (s *Service) instanceNetworkMetadata(ctx context.Context, r InstanceRecord, version, item string) ([]byte, string, int) {
	if len(r.Data.NetworkInterfaces) == 0 {
		return nil, "", http.StatusNotFound
	}
	switch item {
	case "network":
		return metadataText("interfaces/")
	case "network/interfaces":
		return metadataText("macs/")
	case "network/interfaces/macs":
		macs := make([]string, 0, len(r.Data.NetworkInterfaces))
		for _, eni := range r.Data.NetworkInterfaces {
			macs = append(macs, str(eni.MacAddress)+"/")
		}
		slices.Sort(macs)
		return metadataText(strings.Join(macs, "\n"))
	}
	const prefix = "network/interfaces/macs/"
	if !strings.HasPrefix(item, prefix) {
		return nil, "", http.StatusNotFound
	}
	mac, attribute, _ := strings.Cut(strings.TrimPrefix(item, prefix), "/")
	const category = "meta-data/network/interfaces/macs/{{mac}}/"
	versionAttribute := attribute
	if attribute == "ipv4-associations" || strings.HasPrefix(attribute, "ipv4-associations/") {
		versionAttribute = "ipv4-associations/{{public-ip}}"
	}
	if !metadataVersionAllows(version, category+versionAttribute) {
		return nil, "", http.StatusNotFound
	}
	for _, eni := range r.Data.NetworkInterfaces {
		if mac != str(eni.MacAddress) {
			continue
		}
		switch attribute {
		case "":
			names := []string{"interface-id", "mac", "owner-id", "subnet-id", "subnet-ipv4-cidr-block", "vpc-id", "vpc-ipv4-cidr-block", "vpc-ipv4-cidr-blocks"}
			if eni.Attachment != nil && eni.Attachment.DeviceIndex != nil {
				names = append(names, "device-number")
			}
			if str(eni.PrivateIpAddress) != "" {
				names = append(names, "local-hostname")
			}
			if len(eni.PrivateIpAddresses) != 0 {
				names = append(names, "local-ipv4s")
			}
			if len(eni.Groups) != 0 {
				names = append(names, "security-group-ids", "security-groups")
			}
			if eni.Association != nil && metadataVersionAllows(version, category+"public-ipv4s") {
				names = append(names, "public-ipv4s", "ipv4-associations/")
				if str(eni.Association.PublicDnsName) != "" {
					names = append(names, "public-hostname")
				}
			}
			return metadataDirectory(version, category, names)
		case "public-ipv4s", "ipv4-associations":
			var ips []string
			for _, ip := range eni.PrivateIpAddresses {
				if ip.Association != nil {
					ips = append(ips, str(ip.Association.PublicIp))
				}
			}
			if len(ips) > 0 {
				return metadataText(strings.Join(ips, "\n"))
			}
		case "public-hostname":
			if eni.Association != nil && str(eni.Association.PublicDnsName) != "" {
				return metadataText(str(eni.Association.PublicDnsName))
			}
		case "device-number":
			if eni.Attachment != nil && eni.Attachment.DeviceIndex != nil {
				return metadataText(strconv.Itoa(int(*eni.Attachment.DeviceIndex)))
			}
		case "interface-id":
			return metadataText(str(eni.NetworkInterfaceId))
		case "local-hostname":
			if str(eni.PrivateIpAddress) != "" {
				return metadataText(privateDNSName(r.Key.Scope, str(eni.PrivateIpAddress)))
			}
		case "local-ipv4s":
			if len(eni.PrivateIpAddresses) != 0 {
				ips := make([]string, 0, len(eni.PrivateIpAddresses))
				for _, ip := range eni.PrivateIpAddresses {
					ips = append(ips, str(ip.PrivateIpAddress))
				}
				return metadataText(strings.Join(ips, "\n"))
			}
		case "mac":
			return metadataText(mac)
		case "owner-id":
			return metadataText(str(eni.OwnerId))
		case "security-group-ids", "security-groups":
			if len(eni.Groups) != 0 {
				groups := make([]string, 0, len(eni.Groups))
				for _, group := range eni.Groups {
					if attribute == "security-group-ids" {
						groups = append(groups, str(group.GroupId))
					} else {
						groups = append(groups, str(group.GroupName))
					}
				}
				return metadataText(strings.Join(groups, "\n"))
			}
		case "subnet-id":
			return metadataText(str(eni.SubnetId))
		case "vpc-id":
			return metadataText(str(eni.VpcId))
		case "subnet-ipv4-cidr-block", "vpc-ipv4-cidr-block", "vpc-ipv4-cidr-blocks":
			var cidrs []string
			err := s.repository.View(ctx, func(tx Reader) error {
				retained, err := tx.NetworkInterface(ResourceKey{Scope: r.Key.Scope, ID: str(eni.NetworkInterfaceId)})
				if err != nil {
					return err
				}
				if attribute == "subnet-ipv4-cidr-block" {
					subnet, err := interfaceSubnet(tx, retained)
					if err != nil {
						return err
					}
					if cidr := str(subnet.Data.CidrBlock); cidr != "" {
						cidrs = append(cidrs, cidr)
					}
				} else {
					vpc, err := tx.VPC(ResourceKey{Scope: interfaceSubnetKey(retained).Scope, ID: str(eni.VpcId)})
					if err != nil {
						return err
					}
					if attribute == "vpc-ipv4-cidr-block" {
						if cidr := str(vpc.Data.CidrBlock); cidr != "" {
							cidrs = append(cidrs, cidr)
						}
					} else {
						for _, association := range vpc.Data.CidrBlockAssociationSet {
							if association.CidrBlockState != nil && str(association.CidrBlockState.State) == "associated" {
								cidrs = append(cidrs, str(association.CidrBlock))
							}
						}
					}
				}
				return nil
			})
			if err != nil {
				return nil, "", http.StatusInternalServerError
			}
			if len(cidrs) != 0 {
				return metadataText(strings.Join(cidrs, "\n"))
			}
		default:
			if public, ok := strings.CutPrefix(attribute, "ipv4-associations/"); ok {
				for _, ip := range eni.PrivateIpAddresses {
					if ip.Association != nil && str(ip.Association.PublicIp) == public {
						return metadataText(str(ip.PrivateIpAddress))
					}
				}
			}
		}
		break
	}
	// TODO: Comeback add IPv6 metadata with its native network owner;
	// network-card requires multi-card support (the native single-card path is absent).
	return nil, "", http.StatusNotFound
}
