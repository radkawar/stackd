package ec2

import (
	"context"
	"errors"

	api "stackd/internal/awsapi/ec2"
)

func networkInterfaceProjection(ctx context.Context, tx Reader, record NetworkInterfaceRecord) (api.NetworkInterface, error) {
	d := api.CloneNetworkInterface(record.Data)
	d.Association = nil
	d.PublicDnsName = new(api.String(""))
	for i := range d.PrivateIpAddresses {
		d.PrivateIpAddresses[i].Association = nil
	}
	rows, err := tx.PublicAddresses(record.Key.Scope)
	if err != nil {
		return d, err
	}
	var vpc VPCRecord
	for _, row := range rows {
		if str(row.Data.NetworkInterfaceId) != record.Key.ID || str(row.Data.PublicIp) == "" {
			continue
		}
		if vpc.Key.ID == "" {
			vpc, err = tx.VPC(ResourceKey{Scope: interfaceSubnetKey(record).Scope, ID: str(d.VpcId)})
			if err != nil {
				return d, err
			}
		}
		dns := ""
		if vpc.DNSSupport && vpc.DNSHostnames {
			dns = publicDNSName(record.Key.Scope, str(row.Data.PublicIp))
		}
		owner := record.Key.Scope.AccountID
		if row.Automatic {
			owner = "amazon"
		}
		association := &api.NetworkInterfaceAssociation{AllocationId: row.Data.AllocationId, AssociationId: row.Data.AssociationId, PublicIp: row.Data.PublicIp, PublicDnsName: new(api.String(dns)), IpOwnerId: new(api.String(owner))}
		for i := range d.PrivateIpAddresses {
			if str(d.PrivateIpAddresses[i].PrivateIpAddress) == str(row.Data.PrivateIpAddress) {
				d.PrivateIpAddresses[i].Association = association
			}
		}
		if str(d.PrivateIpAddress) == str(row.Data.PrivateIpAddress) {
			d.Association = association
			d.PublicDnsName = association.PublicDnsName
		}
	}
	return d, nil
}

func admitAutomaticPublicIPv4(ctx context.Context, tx Transaction, eni NetworkInterfaceRecord) error {
	id, err := tx.NextID(scopeFor(ctx), "public-auto")
	if err != nil {
		return err
	}
	ip, err := allocatePublicIPv4(tx, scopeFor(ctx))
	if err != nil {
		return err
	}
	return tx.PutPublicAddress(PublicAddressRecord{Key: key(ctx, id), Automatic: true, Data: api.Address{PublicIp: new(api.String(ip)), NetworkInterfaceId: new(api.String(eni.Key.ID)), PrivateIpAddress: eni.Data.PrivateIpAddress, Domain: new(api.DomainType("vpc")), PublicIpv4Pool: new(api.String("amazon")), NetworkBorderGroup: new(api.String(scopeFor(ctx).Region))}})
}

func restoreAutomaticPublicIPv4(ctx context.Context, tx Transaction, eniID string) error {
	if eniID == "" {
		return nil
	}
	eni, err := tx.NetworkInterface(key(ctx, eniID))
	if errors.Is(err, ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	if eni.Data.Attachment == nil {
		return nil
	}
	if id := str(eni.Data.Attachment.InstanceId); id != "" {
		instance, err := tx.Instance(key(ctx, id))
		if err != nil {
			return err
		}
		if state := instanceState(instance); state != "running" && state != "pending" {
			return nil
		}
	}
	rows, err := tx.PublicAddresses(scopeFor(ctx))
	if err != nil {
		return err
	}
	for _, row := range rows {
		if !row.Automatic && str(row.Data.NetworkInterfaceId) == eniID && str(row.Data.PrivateIpAddress) == str(eni.Data.PrivateIpAddress) {
			return nil
		}
	}
	for _, row := range rows {
		if row.Automatic && str(row.Data.NetworkInterfaceId) == eniID && row.Data.PublicIp == nil {
			ip, err := allocatePublicIPv4(tx, scopeFor(ctx))
			if err != nil {
				return err
			}
			row.Data.PublicIp = new(api.String(ip))
			if err := tx.PutPublicAddress(row); err != nil {
				return err
			}
		}
	}
	return nil
}

func releaseInterfacePublicAddresses(ctx context.Context, tx Transaction, eniID string, remove bool) error {
	rows, err := tx.PublicAddresses(scopeFor(ctx))
	if err != nil {
		return err
	}
	for _, row := range rows {
		if str(row.Data.NetworkInterfaceId) != eniID {
			continue
		}
		if row.Automatic {
			if remove {
				if err := tx.DeletePublicAddress(row.Key); err != nil {
					return err
				}
				continue
			}
			row.Data.PublicIp = nil
		} else {
			if !remove {
				continue
			}
			clearAddressAssociation(&row)
		}
		if err := tx.PutPublicAddress(row); err != nil {
			return err
		}
	}
	return nil
}

func (s *Service) wakePublicNetwork(ctx context.Context, tx Transaction, eniIDs ...string) error {
	seen := map[string]bool{}
	for _, id := range eniIDs {
		if id == "" || seen[id] {
			continue
		}
		seen[id] = true
		eni, err := tx.NetworkInterface(key(ctx, id))
		if errors.Is(err, ErrNotFound) {
			continue
		}
		if err != nil {
			return err
		}
		if eni.Data.Attachment == nil || str(eni.Data.Attachment.InstanceId) == "" {
			continue
		}
		record, err := tx.Instance(key(ctx, str(eni.Data.Attachment.InstanceId)))
		if err != nil {
			return err
		}
		if instanceState(record) != "running" && instanceState(record) != "pending" {
			continue
		}
		record.Generation++
		scheduleInstanceObservation(&record, s.clock.Now())
		if err := tx.PutInstance(record); err != nil {
			return err
		}
	}
	return nil
}

func attachedInternetGateway(ctx context.Context, tx Reader, vpcID string) (bool, error) {
	rows, err := tx.InternetGateways(scopeFor(ctx))
	if err != nil {
		return false, err
	}
	for _, row := range rows {
		for _, attachment := range row.Data.Attachments {
			if str(attachment.VpcId) == vpcID && str(attachment.State) == "available" {
				return true, nil
			}
		}
	}
	return false, nil
}
