package ec2

import (
	"context"
	"errors"
	"net/netip"

	api "stackd/internal/awsapi/ec2"
)

// DryRun evaluates current authority even when target parameters are absent or
// refer to deleted resources. Native address controls defer that admission.
func (s *Service) dryRunPublicAddress(ctx context.Context, tx Reader, action, id, ip, association, eniID, instanceID string) error {
	var row PublicAddressRecord
	if id != "" {
		var err error
		row, err = tx.PublicAddress(key(ctx, id))
		if err != nil && !errors.Is(err, ErrNotFound) {
			return err
		}
	} else if ip != "" || association != "" {
		rows, err := tx.PublicAddresses(scopeFor(ctx))
		if err != nil {
			return err
		}
		for _, candidate := range rows {
			if !candidate.Automatic && (ip != "" && str(candidate.Data.PublicIp) == ip || association != "" && str(candidate.Data.AssociationId) == association) {
				row = candidate
				id = row.Key.ID
				break
			}
		}
	}
	if id == "" {
		id = "*"
	}
	if err := s.authorizeWith(ctx, action, "elastic-ip", id, row.Data.Tags, addressConditions(row.Data)); err != nil {
		return err
	}
	if action == "DisassociateAddress" {
		eniID = str(row.Data.NetworkInterfaceId)
	}
	if instanceID != "" {
		instance, err := tx.Instance(key(ctx, instanceID))
		if err != nil && !errors.Is(err, ErrNotFound) {
			return err
		}
		if err := s.authorizeWith(ctx, action, "instance", instanceID, instance.Data.Tags, instanceProfileConditions(instance)); err != nil {
			return err
		}
		if eniID == "" && len(instance.Data.NetworkInterfaces) == 1 {
			eniID = str(instance.Data.NetworkInterfaces[0].NetworkInterfaceId)
		}
	}
	if eniID != "" {
		if err := s.authorizeAddressInterface(ctx, tx, action, eniID); err != nil {
			return err
		}
	}
	return dryRun(new(api.Boolean(true)))
}

func (s *Service) authorizeAddressInterface(ctx context.Context, tx Reader, action, id string) error {
	eni, err := tx.NetworkInterface(key(ctx, id))
	if err != nil && !errors.Is(err, ErrNotFound) {
		return err
	}
	return s.authorizeWith(ctx, action, "network-interface", id, eni.Data.TagSet, addressInterfaceConditions(scopeFor(ctx), id, eni))
}

func addressInterfaceConditions(scope Scope, id string, eni NetworkInterfaceRecord) map[string][]string {
	conditions := map[string][]string{"ec2:NetworkInterfaceID": {id}}
	if str(eni.Data.VpcId) != "" {
		conditions["ec2:Vpc"] = []string{resourceARN(scope, "vpc", str(eni.Data.VpcId))}
	}
	if str(eni.Data.SubnetId) != "" {
		conditions["ec2:Subnet"] = []string{resourceARN(scope, "subnet", str(eni.Data.SubnetId))}
	}
	if eni.Data.AvailabilityZone != nil {
		conditions["ec2:AvailabilityZone"] = []string{str(eni.Data.AvailabilityZone)}
	}
	return conditions
}

func validatePublicIPv4(value string) error {
	if value == "" {
		return nil
	}
	ip, err := netip.ParseAddr(value)
	if err != nil || !ip.Is4() {
		return failure("InvalidParameterValue", "Invalid public IPv4 address: "+value)
	}
	return nil
}
