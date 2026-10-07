package ec2

import (
	"context"
	api "stackd/internal/awsapi/ec2"
)

func (s *Service) associateNatGatewayAddress(ctx context.Context, tx Transaction, in *api.AssociateNatGatewayAddressRequest) (*api.AssociateNatGatewayAddressResult, error) {
	v, err := s.natGatewayForAction(ctx, tx, "AssociateNatGatewayAddress", str(in.NatGatewayId))
	if err != nil {
		return nil, err
	}
	if err = dryRun(in.DryRun); err != nil {
		return nil, err
	}
	if str(v.Data.State) != "available" || str(v.Data.ConnectivityType) != "public" {
		return nil, failure("InvalidParameterValue", "An available public NAT gateway is required.")
	}
	if in.AvailabilityZone != nil || in.AvailabilityZoneId != nil {
		return nil, unsupported("Regional NAT address association is not supported.")
	}
	if err = s.addNatAddresses(ctx, tx, "AssociateNatGatewayAddress", &v, stringsOf(in.AllocationIds), stringsOf(in.PrivateIpAddresses), 0); err != nil {
		return nil, err
	}
	if err = tx.PutNatGateway(v); err != nil {
		return nil, err
	}
	return &api.AssociateNatGatewayAddressResult{NatGatewayId: copyPointer(in.NatGatewayId), NatGatewayAddresses: v.Data.NatGatewayAddresses}, nil
}
func validateNatDrain(seconds *api.DrainSeconds) error {
	if seconds != nil && (*seconds < 1 || *seconds > 4000) {
		return failure("InvalidParameterValue", "Drain duration must be between 1 and 4000 seconds.")
	}
	return nil
}
func (s *Service) disassociateNatGatewayAddress(ctx context.Context, tx Transaction, in *api.DisassociateNatGatewayAddressRequest) (*api.DisassociateNatGatewayAddressResult, error) {
	v, err := s.natGatewayForAction(ctx, tx, "DisassociateNatGatewayAddress", str(in.NatGatewayId))
	if err != nil {
		return nil, err
	}
	if err = dryRun(in.DryRun); err != nil {
		return nil, err
	}
	if str(v.Data.State) != "available" || str(v.Data.ConnectivityType) != "public" {
		return nil, failure("InvalidParameterValue", "An available public NAT gateway is required.")
	}
	if err = validateNatDrain(in.MaxDrainDurationSeconds); err != nil {
		return nil, err
	}
	selected := map[string]bool{}
	for _, id := range in.AssociationIds {
		selected[string(id)] = true
	}
	if len(selected) == 0 {
		return nil, failure("MissingParameter", "AssociationIds are required.")
	}
	if err = s.removeNatAddresses(ctx, tx, &v, selected, true); err != nil {
		return nil, err
	}
	return &api.DisassociateNatGatewayAddressResult{NatGatewayId: copyPointer(in.NatGatewayId), NatGatewayAddresses: v.Data.NatGatewayAddresses}, nil
}
func (s *Service) assignPrivateNatGatewayAddress(ctx context.Context, tx Transaction, in *api.AssignPrivateNatGatewayAddressRequest) (*api.AssignPrivateNatGatewayAddressResult, error) {
	v, err := s.natGatewayForAction(ctx, tx, "AssignPrivateNatGatewayAddress", str(in.NatGatewayId))
	if err != nil {
		return nil, err
	}
	if err = dryRun(in.DryRun); err != nil {
		return nil, err
	}
	if str(v.Data.State) != "available" || str(v.Data.ConnectivityType) != "private" {
		return nil, failure("InvalidParameterValue", "An available private NAT gateway is required.")
	}
	count := 0
	if in.PrivateIpAddressCount != nil {
		count = int(*in.PrivateIpAddressCount)
	}
	if err = s.addNatAddresses(ctx, tx, "AssignPrivateNatGatewayAddress", &v, nil, stringsOf(in.PrivateIpAddresses), count); err != nil {
		return nil, err
	}
	if err = tx.PutNatGateway(v); err != nil {
		return nil, err
	}
	return &api.AssignPrivateNatGatewayAddressResult{NatGatewayId: copyPointer(in.NatGatewayId), NatGatewayAddresses: v.Data.NatGatewayAddresses}, nil
}
func (s *Service) unassignPrivateNatGatewayAddress(ctx context.Context, tx Transaction, in *api.UnassignPrivateNatGatewayAddressRequest) (*api.UnassignPrivateNatGatewayAddressResult, error) {
	v, err := s.natGatewayForAction(ctx, tx, "UnassignPrivateNatGatewayAddress", str(in.NatGatewayId))
	if err != nil {
		return nil, err
	}
	if err = dryRun(in.DryRun); err != nil {
		return nil, err
	}
	if str(v.Data.State) != "available" || str(v.Data.ConnectivityType) != "private" {
		return nil, failure("InvalidParameterValue", "An available private NAT gateway is required.")
	}
	if err = validateNatDrain(in.MaxDrainDurationSeconds); err != nil {
		return nil, err
	}
	selected := map[string]bool{}
	for _, ip := range in.PrivateIpAddresses {
		selected[string(ip)] = true
	}
	if len(selected) == 0 {
		return nil, failure("MissingParameter", "PrivateIpAddresses are required.")
	}
	if err = s.removeNatAddresses(ctx, tx, &v, selected, false); err != nil {
		return nil, err
	}
	return &api.UnassignPrivateNatGatewayAddressResult{NatGatewayId: copyPointer(in.NatGatewayId), NatGatewayAddresses: v.Data.NatGatewayAddresses}, nil
}
