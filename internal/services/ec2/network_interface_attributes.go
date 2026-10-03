package ec2

import (
	"context"
	"strings"

	api "stackd/internal/awsapi/ec2"
)

func (s *Service) describeNetworkInterfaceAttribute(ctx context.Context, tx Transaction, in *api.DescribeNetworkInterfaceAttributeRequest) (*api.DescribeNetworkInterfaceAttributeResult, error) {
	id := str(in.NetworkInterfaceId)
	record, err := s.authorizeNetworkInterface(ctx, tx, "DescribeNetworkInterfaceAttribute", id)
	if err != nil {
		return nil, err
	}
	if err := dryRun(in.DryRun); err != nil {
		return nil, err
	}
	if in.Attribute == nil {
		return nil, failure("InvalidParameterCombination", "No attributes specified.")
	}
	if err := requireNetworkInterface(record, id); err != nil {
		return nil, err
	}
	out := &api.DescribeNetworkInterfaceAttributeResult{NetworkInterfaceId: new(api.String(id))}
	switch str(in.Attribute) {
	case "description":
		out.Description = &api.AttributeValue{Value: copyPointer(record.Data.Description)}
	case "groupSet":
		out.Groups = record.Data.Groups
	case "sourceDestCheck":
		out.SourceDestCheck = &api.AttributeBooleanValue{Value: copyPointer(record.Data.SourceDestCheck)}
	case "attachment":
		out.Attachment = record.Data.Attachment
	case "associatePublicIpAddress":
		rows, err := tx.PublicAddresses(scopeFor(ctx))
		if err != nil {
			return nil, err
		}
		enabled := false
		for _, row := range rows {
			enabled = enabled || row.Automatic && str(row.Data.NetworkInterfaceId) == id
		}
		out.AssociatePublicIpAddress = new(api.Boolean(enabled))
	default:
		return nil, failure("InvalidParameterValue", "Value ("+str(in.Attribute)+") for parameter attribute is invalid. Unknown attribute.")
	}
	return out, nil
}

func (s *Service) modifyNetworkInterfaceAttribute(ctx context.Context, tx Transaction, in *api.ModifyNetworkInterfaceAttributeRequest) (*emptyResult, error) {
	id := str(in.NetworkInterfaceId)
	record, err := s.authorizeNetworkInterface(ctx, tx, "ModifyNetworkInterfaceAttribute", id)
	if err != nil {
		return nil, err
	}
	var groups []SecurityGroupRecord
	if len(in.Groups) > 0 {
		groups, err = s.networkInterfaceGroups(ctx, tx, "ModifyNetworkInterfaceAttribute", in.Groups, str(record.Data.VpcId))
		if err != nil {
			return nil, err
		}
	}
	if err := dryRun(in.DryRun); err != nil {
		return nil, err
	}
	if err := requireNetworkInterface(record, id); err != nil {
		return nil, err
	}
	if err := ownedUnattachedNetworkInterface(record); err != nil {
		return nil, err
	}
	if in.AssociatePublicIpAddress != nil || len(in.AssociatedSubnetIds) > 0 || in.Attachment != nil || in.ConnectionTrackingSpecification != nil || in.EnaSrdSpecification != nil || in.EnablePrimaryIpv6 != nil {
		// TODO: Comeback implement automatic public IPv4 attribute mutation,
		// multi-subnet/instance attachment, connection tracking, ENA SRD and primary IPv6 prerequisites.
		return nil, unsupported("Automatic public IPv4 attributes, multi-subnet/instance attachment, connection tracking, ENA SRD and primary IPv6 mutations are not implemented.")
	}
	attributes := []string{}
	if in.SourceDestCheck != nil {
		attributes = append(attributes, "sourceDestCheck")
	}
	if in.Description != nil {
		attributes = append(attributes, "description")
	}
	if len(in.Groups) > 0 {
		attributes = append(attributes, "groupSet")
	}
	if len(attributes) == 0 {
		return nil, failure("InvalidParameterCombination", "No attributes specified.")
	}
	if len(attributes) > 1 {
		return nil, failure("InvalidParameterCombination", "Fields for multiple attribute types specified: "+strings.Join(attributes, ", "))
	}
	if in.Description != nil {
		if in.Description.Value == nil {
			return nil, failure("MissingParameter", "The attribute value must be specified.")
		}
		if err := validateNetworkInterfaceDescription(str(in.Description.Value)); err != nil {
			return nil, err
		}
		record.Data.Description = copyPointer(in.Description.Value)
	}
	if in.SourceDestCheck != nil {
		if in.SourceDestCheck.Value == nil {
			return nil, failure("MissingParameter", "The attribute value must be specified.")
		}
		record.Data.SourceDestCheck = copyPointer(in.SourceDestCheck.Value)
	}
	if len(in.Groups) > 0 {
		subnet, err := interfaceSubnet(tx, record)
		if err != nil {
			return nil, err
		}
		if err := validateNetworkInterfaceGroups(groups, subnet, false); err != nil {
			return nil, err
		}
		record.Data.Groups = networkInterfaceGroupIdentifiers(groups)
	}
	if err := tx.PutNetworkInterface(record); err != nil {
		return nil, err
	}
	return &emptyResult{}, nil
}

func (s *Service) resetNetworkInterfaceAttribute(ctx context.Context, tx Transaction, in *api.ResetNetworkInterfaceAttributeRequest) (*emptyResult, error) {
	// SourceDestCheck is a presence-style query flag, not a boolean or an
	// attribute-name enum. Nonempty values fail even for DryRun or deleted IDs.
	if in.SourceDestCheck != nil && str(in.SourceDestCheck) != "" {
		return nil, failure("InvalidRequest", "The request received was invalid.")
	}
	id := str(in.NetworkInterfaceId)
	record, err := s.authorizeNetworkInterface(ctx, tx, "ResetNetworkInterfaceAttribute", id)
	if err != nil {
		return nil, err
	}
	if err := dryRun(in.DryRun); err != nil {
		return nil, err
	}
	if in.SourceDestCheck == nil {
		return nil, failure("InvalidParameterCombination", "No attributes specified.")
	}
	if err := requireNetworkInterface(record, id); err != nil {
		return nil, err
	}
	if err := ownedUnattachedNetworkInterface(record); err != nil {
		return nil, err
	}
	record.Data.SourceDestCheck = new(api.Boolean(true))
	if err := tx.PutNetworkInterface(record); err != nil {
		return nil, err
	}
	return &emptyResult{}, nil
}
