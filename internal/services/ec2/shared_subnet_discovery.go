package ec2

import (
	"context"
	"errors"
)

func (s *Service) visibleVPCs(ctx context.Context, tx Reader, action string) ([]VPCRecord, error) {
	out, err := tx.VPCs(scopeFor(ctx))
	if err != nil || s.sharedSubnets == nil {
		return out, err
	}
	identities, err := s.sharedSubnets.SharedSubnets(ctx, scopeFor(ctx), "ec2:"+action)
	if err != nil {
		return nil, err
	}
	seen := make(map[ResourceKey]bool, len(out))
	for _, vpc := range out {
		seen[vpc.Key] = true
	}
	for _, identity := range identities {
		subnet, err := s.currentSharedSubnet(ctx, tx, identity)
		if errors.Is(err, ErrNotFound) {
			continue
		}
		if err != nil {
			return nil, err
		}
		k := ResourceKey{Scope: subnet.Key.Scope, ID: str(subnet.Data.VpcId)}
		if seen[k] {
			continue
		}
		if err := s.authorizeSharedNetwork(ctx, action, "vpc", k, subnet, nil); err != nil {
			continue
		}
		vpc, err := tx.VPC(k)
		if err != nil {
			return nil, err
		}
		vpc.Data.Tags = nil
		out = append(out, vpc)
		seen[k] = true
	}
	return out, nil
}

func (s *Service) visibleNetworkInterfaces(ctx context.Context, tx Reader) ([]NetworkInterfaceRecord, error) {
	rows, err := tx.RegionalNetworkInterfaces(scopeFor(ctx))
	if err != nil {
		return nil, err
	}
	out := rows[:0]
	for _, row := range rows {
		if row.Key.Scope == scopeFor(ctx) {
			out = append(out, row)
		} else if interfaceSubnetKey(row).Scope == scopeFor(ctx) {
			// Network owners can inspect participant interfaces, never mutate
			// them or see their private tags through this read projection.
			row.Data.TagSet = nil
			out = append(out, row)
		}
	}
	return out, nil
}

func (s *Service) visibleSecurityGroups(ctx context.Context, tx Reader) ([]SecurityGroupRecord, error) {
	rows, err := tx.RegionalSecurityGroups(scopeFor(ctx))
	if err != nil {
		return nil, err
	}
	out := rows[:0]
	for _, row := range rows {
		if row.Key.Scope == scopeFor(ctx) {
			out = append(out, row)
		} else if groupVPCScope(row) == scopeFor(ctx) {
			row.Data.Tags = nil
			out = append(out, row)
		}
	}
	return out, nil
}

func (s *Service) sharedNetworkVPCs(ctx context.Context, tx Reader, action string) (map[Scope]map[string]VPCRecord, error) {
	vpcs, err := s.visibleVPCs(ctx, tx, action)
	if err != nil {
		return nil, err
	}
	out := map[Scope]map[string]VPCRecord{}
	for _, vpc := range vpcs {
		if vpc.Key.Scope == scopeFor(ctx) {
			continue
		}
		if out[vpc.Key.Scope] == nil {
			out[vpc.Key.Scope] = map[string]VPCRecord{}
		}
		out[vpc.Key.Scope][vpc.Key.ID] = vpc
	}
	return out, nil
}

func (s *Service) visibleRouteTables(ctx context.Context, tx Reader) ([]RouteTableRecord, error) {
	out, err := tx.RouteTables(scopeFor(ctx))
	if err != nil {
		return nil, err
	}
	scopes, err := s.sharedNetworkVPCs(ctx, tx, "DescribeRouteTables")
	if err != nil {
		return nil, err
	}
	for scope, vpcs := range scopes {
		rows, err := tx.RouteTables(scope)
		if err != nil {
			return nil, err
		}
		for _, row := range rows {
			if _, ok := vpcs[str(row.Data.VpcId)]; ok {
				row.Data.Tags = nil
				out = append(out, row)
			}
		}
	}
	return out, nil
}

func (s *Service) visibleNetworkACLs(ctx context.Context, tx Reader) ([]NetworkACLRecord, error) {
	out, err := tx.NetworkACLs(scopeFor(ctx))
	if err != nil {
		return nil, err
	}
	scopes, err := s.sharedNetworkVPCs(ctx, tx, "DescribeNetworkAcls")
	if err != nil {
		return nil, err
	}
	for scope, vpcs := range scopes {
		rows, err := tx.NetworkACLs(scope)
		if err != nil {
			return nil, err
		}
		for _, row := range rows {
			if _, ok := vpcs[str(row.Data.VpcId)]; ok {
				row.Data.Tags = nil
				out = append(out, row)
			}
		}
	}
	return out, nil
}

func (s *Service) visibleInternetGateways(ctx context.Context, tx Reader) ([]InternetGatewayRecord, error) {
	out, err := tx.InternetGateways(scopeFor(ctx))
	if err != nil {
		return nil, err
	}
	scopes, err := s.sharedNetworkVPCs(ctx, tx, "DescribeInternetGateways")
	if err != nil {
		return nil, err
	}
	for scope, vpcs := range scopes {
		rows, err := tx.InternetGateways(scope)
		if err != nil {
			return nil, err
		}
		for _, row := range rows {
			for _, attachment := range row.Data.Attachments {
				if _, ok := vpcs[str(attachment.VpcId)]; ok {
					row.Data.Tags = nil
					out = append(out, row)
					break
				}
			}
		}
	}
	return out, nil
}

func (s *Service) visibleDHCPOptions(ctx context.Context, tx Reader) ([]DHCPOptionsRecord, error) {
	out, err := tx.DHCPOptionsSets(scopeFor(ctx))
	if err != nil {
		return nil, err
	}
	scopes, err := s.sharedNetworkVPCs(ctx, tx, "DescribeDhcpOptions")
	if err != nil {
		return nil, err
	}
	seen := map[ResourceKey]bool{}
	for scope, vpcs := range scopes {
		for _, vpc := range vpcs {
			k := ResourceKey{Scope: scope, ID: str(vpc.Data.DhcpOptionsId)}
			if k.ID == "" || k.ID == "default" || seen[k] {
				continue
			}
			row, err := tx.DHCPOptions(k)
			if err != nil {
				return nil, err
			}
			row.Data.Tags = nil
			out = append(out, row)
			seen[k] = true
		}
	}
	return out, nil
}
