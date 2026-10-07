package integrations

import (
	"context"
	"errors"
	"fmt"
	"net/netip"

	api "stackd/internal/awsapi/ec2"
	"stackd/internal/services/cloudformation"
	"stackd/internal/services/ec2"
)

type cfnEC2RouteTable struct{ commands StepFunctionsCommands }

func (h cfnEC2RouteTable) Validate(p cloudformation.Properties) error {
	if err := cfnComputeProperties(p, "VpcId", "Tags"); err != nil {
		return err
	}
	if err := cfnComputeRequired(p, "VpcId"); err != nil {
		return err
	}
	if err := cfnComputeStrings(p, "VpcId"); err != nil {
		return err
	}
	_, err := cfnComputeTags(p)
	return err
}
func (h cfnEC2RouteTable) Replacement(a, b cloudformation.Properties) (bool, error) {
	return cfnComputeChanged(a, b, "VpcId"), h.Validate(b)
}
func (h cfnEC2RouteTable) describe(ctx context.Context, id string) (api.RouteTable, error) {
	out, err := cfnComputeCall[api.DescribeRouteTablesResult](ctx, h.commands, "ec2", "DescribeRouteTables", map[string]any{"RouteTableIds": []string{id}})
	if err != nil {
		return api.RouteTable{}, err
	}
	if len(out.RouteTables) != 1 {
		return api.RouteTable{}, cfnEC2NotFound("route table")
	}
	return out.RouteTables[0], nil
}
func (h cfnEC2RouteTable) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	input := map[string]any{"VpcId": r.Properties["VpcId"], "TagSpecifications": cfnEC2NetworkTagSpecifications(r, "route-table")}
	if r.Token != "" {
		input["ClientToken"] = cfnComputeHash(r.StackID + "/" + r.LogicalID + "/" + r.Token)
	}
	id, err := cfnEC2NativeRecover(ctx, h.commands, r)
	if err != nil {
		return cfnEC2IDResult(id), err
	}
	if id == "" {
		out, e := cfnComputeCall[api.CreateRouteTableResult](cfnEC2NativeContext(ctx, r, "create"), h.commands, "ec2", "CreateRouteTable", input)
		if e != nil {
			return cloudformation.ResourceResult{}, e
		}
		id = cfnComputeValue(out.RouteTable.RouteTableId)
	}
	result := cfnEC2IDResult(id)
	result.Attributes = map[string]any{"RouteTableId": id}
	return result, cfnEC2NativeOwned(ctx, h.commands, r, id)
}
func (h cfnEC2RouteTable) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if replacement, err := h.Replacement(r.Previous, r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	} else if replacement {
		return cloudformation.ResourceResult{}, fmt.Errorf("route table requires replacement")
	}
	v, err := h.describe(ctx, r.PhysicalID)
	result := cfnEC2IDResult(r.PhysicalID)
	result.Attributes = map[string]any{"RouteTableId": r.PhysicalID}
	if err != nil {
		return result, err
	}
	if err = cfnEC2NativeOwned(ctx, h.commands, r, r.PhysicalID); err != nil {
		return result, err
	}
	return result, cfnEC2NetworkUpdateTags(ctx, h.commands, r, r.PhysicalID, cfnEC2Tags(v.Tags))
}
func (h cfnEC2RouteTable) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	_, err := h.describe(ctx, r.PhysicalID)
	if err != nil {
		return cfnEC2Absent(err)
	}
	if err = cfnEC2NativeOwned(ctx, h.commands, r, r.PhysicalID); err != nil {
		return err
	}
	return cfnEC2Absent(cfnComputeRun(cfnEC2NativeContext(ctx, r, "mutate"), h.commands, "ec2", "DeleteRouteTable", map[string]any{"RouteTableId": r.PhysicalID}))
}
func (h cfnEC2RouteTable) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	v, err := h.describe(ctx, r.PhysicalID)
	if err != nil {
		return nil, err
	}
	if err = cfnEC2NativeOwned(ctx, h.commands, r, r.PhysicalID); err != nil {
		return nil, err
	}
	return cloudformation.Properties{"RouteTableId": cfnComputeValue(v.RouteTableId), "VpcId": cfnComputeValue(v.VpcId), "Tags": cfnEC2Tags(v.Tags)}, nil
}
func (h cfnEC2RouteTable) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	var result []cloudformation.ResourceDescription
	for input := map[string]any{}; ; {
		out, err := cfnComputeCall[api.DescribeRouteTablesResult](ctx, h.commands, "ec2", "DescribeRouteTables", input)
		if err != nil {
			return nil, err
		}
		for _, v := range out.RouteTables {
			id := cfnComputeValue(v.RouteTableId)
			if !r.CloudControl && cfnEC2NativeOwned(ctx, h.commands, r, id) != nil {
				continue
			}
			result = append(result, cloudformation.ResourceDescription{Identifier: id, Properties: cloudformation.Properties{"RouteTableId": id, "VpcId": cfnComputeValue(v.VpcId), "Tags": cfnEC2Tags(v.Tags)}})
		}
		if cfnComputeValue(out.NextToken) == "" {
			return result, nil
		}
		input["NextToken"] = cfnComputeValue(out.NextToken)
	}
}

type cfnEC2Route struct{ commands StepFunctionsCommands }

func (h cfnEC2Route) Validate(p cloudformation.Properties) error {
	if err := cfnComputeProperties(p, "RouteTableId", "DestinationCidrBlock", "DestinationIpv6CidrBlock", "GatewayId", "NatGatewayId"); err != nil {
		return err
	}
	if err := cfnComputeRequired(p, "RouteTableId"); err != nil {
		return err
	}
	if err := cfnComputeStrings(p, "RouteTableId", "DestinationCidrBlock", "DestinationIpv6CidrBlock", "GatewayId", "NatGatewayId"); err != nil {
		return err
	}
	if (p["DestinationCidrBlock"] == nil) == (p["DestinationIpv6CidrBlock"] == nil) {
		return fmt.Errorf("exactly one route destination CIDR is required")
	}
	if (p["GatewayId"] == nil) == (p["NatGatewayId"] == nil) {
		return fmt.Errorf("exactly one implemented route target GatewayId or NatGatewayId is required")
	}
	_, err := cfnEC2RouteDestination(p)
	return err
}
func cfnEC2RouteDestination(p cloudformation.Properties) (string, error) {
	value := cfnComputeString(p, "DestinationCidrBlock")
	ipv6 := false
	if value == "" {
		value = cfnComputeString(p, "DestinationIpv6CidrBlock")
		ipv6 = true
	}
	prefix, err := netip.ParsePrefix(value)
	if err != nil || prefix.Addr().Is4() == ipv6 || prefix.Addr().Is4In6() {
		return "", fmt.Errorf("invalid route destination CIDR")
	}
	return prefix.Masked().String(), nil
}
func (h cfnEC2Route) Replacement(a, b cloudformation.Properties) (bool, error) {
	if err := h.Validate(b); err != nil {
		return false, err
	}
	old, _ := cfnEC2RouteDestination(a)
	next, _ := cfnEC2RouteDestination(b)
	return cfnComputeChanged(a, b, "RouteTableId") || old != next, nil
}
func cfnEC2RouteFind(table api.RouteTable, destination string) (api.Route, bool) {
	for _, route := range table.Routes {
		if cfnComputeValue(route.DestinationCidrBlock) == destination || cfnComputeValue(route.DestinationIpv6CidrBlock) == destination {
			return route, true
		}
	}
	return api.Route{}, false
}
func (h cfnEC2Route) input(p cloudformation.Properties) map[string]any {
	in := cfnComputeCopy(p, "RouteTableId", "DestinationCidrBlock", "DestinationIpv6CidrBlock", "GatewayId", "NatGatewayId")
	destination, _ := cfnEC2RouteDestination(p)
	key := "DestinationCidrBlock"
	if p["DestinationIpv6CidrBlock"] != nil {
		key = "DestinationIpv6CidrBlock"
	}
	in[key] = destination
	return in
}
func (h cfnEC2Route) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	id := cfnComputeString(r.Properties, "RouteTableId")
	destination, _ := cfnEC2RouteDestination(r.Properties)
	slot := id + "|" + destination
	admitted, _, receiptErr := cfnEC2RelationReceipt(ctx, h.commands, r, "")
	result := cfnEC2IDResult("")
	if admitted != "" {
		parent, cidr, e := cfnEC2Pair(admitted, "RouteTableId", "CidrBlock")
		if e == nil {
			result = cfnEC2IDResult(cfnEC2PairID(r, parent, cidr, "RouteTableId", "CidrBlock"))
		}
	}
	if receiptErr != nil && !errors.Is(receiptErr, ec2.ErrNotFound) {
		return result, receiptErr
	}
	table, err := cfnEC2RouteTable(h).describe(ctx, id)
	if err != nil {
		return result, err
	}
	route, exists := cfnEC2RouteFind(table, destination)
	if receiptErr == nil {
		result, e := h.RecoverCreation(ctx, r)
		if e != nil {
			return result, e
		}
		if cfnComputeValue(route.GatewayId) != cfnComputeString(r.Properties, "GatewayId") || cfnComputeValue(route.NatGatewayId) != cfnComputeString(r.Properties, "NatGatewayId") {
			return result, fmt.Errorf("the admitted route has different properties")
		}
		return result, nil
	}
	if exists {
		return cloudformation.ResourceResult{}, fmt.Errorf("cannot adopt an existing route")
	}
	if err = cfnComputeRun(cfnEC2RelationContext(ctx, r, slot), h.commands, "ec2", "CreateRoute", h.input(r.Properties)); err != nil {
		return cfnEC2RelationFailedCreate(ctx, h.commands, r, h.RecoverCreation, err)
	}
	return cfnEC2IDResult(cfnEC2PairID(r, id, destination, "RouteTableId", "CidrBlock")), nil
}
func (h cfnEC2Route) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if replacement, err := h.Replacement(r.Previous, r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	} else if replacement {
		return cloudformation.ResourceResult{}, fmt.Errorf("route requires replacement")
	}
	id := cfnComputeString(r.Properties, "RouteTableId")
	destination, _ := cfnEC2RouteDestination(r.Properties)
	slot := id + "|" + destination
	result := cfnEC2IDResult(r.PhysicalID)
	if _, err := h.Read(ctx, r); err != nil {
		return result, err
	}
	effectCtx := ctx
	if !r.CloudControl {
		effectCtx = cfnEC2RelationContext(ctx, r, slot)
	}
	return result, cfnComputeRun(effectCtx, h.commands, "ec2", "ReplaceRoute", h.input(r.Properties))
}
func (h cfnEC2Route) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	id, destination, err := cfnEC2Pair(r.PhysicalID, "RouteTableId", "CidrBlock")
	if err != nil {
		return err
	}
	table, err := cfnEC2RouteTable(h).describe(ctx, id)
	if err != nil {
		return cfnEC2Absent(err)
	}
	slot := id + "|" + destination
	_, exists := cfnEC2RouteFind(table, destination)
	if !exists {
		if r.CloudControl {
			return nil
		}
		admitted, _, e := cfnEC2RelationReceipt(ctx, h.commands, r, slot)
		if errors.Is(e, ec2.ErrNotFound) {
			return nil
		}
		if e != nil {
			return e
		}
		if admitted != slot {
			return fmt.Errorf("route deletion ID differs from its native receipt")
		}
		return nil
	}
	if err = cfnEC2RelationOwned(ctx, h.commands, r, slot, slot); err != nil {
		return err
	}
	key := "DestinationCidrBlock"
	if prefix, _ := netip.ParsePrefix(destination); prefix.Addr().Is6() {
		key = "DestinationIpv6CidrBlock"
	}
	return cfnEC2Absent(cfnComputeRun(cfnEC2RelationDeletionContext(ctx, r, slot), h.commands, "ec2", "DeleteRoute", map[string]any{"RouteTableId": id, key: destination}))
}
func cfnEC2RouteProjection(id string, route api.Route) cloudformation.Properties {
	p := cloudformation.Properties{"RouteTableId": id}
	for key, value := range map[string]string{"DestinationCidrBlock": cfnComputeValue(route.DestinationCidrBlock), "DestinationIpv6CidrBlock": cfnComputeValue(route.DestinationIpv6CidrBlock), "GatewayId": cfnComputeValue(route.GatewayId), "NatGatewayId": cfnComputeValue(route.NatGatewayId)} {
		if value != "" {
			p[key] = value
		}
	}
	destination := cfnComputeValue(route.DestinationCidrBlock)
	if destination == "" {
		destination = cfnComputeValue(route.DestinationIpv6CidrBlock)
	}
	p["CidrBlock"] = destination
	return p
}
func (h cfnEC2Route) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	id, destination, err := cfnEC2Pair(r.PhysicalID, "RouteTableId", "CidrBlock")
	if err != nil {
		return nil, err
	}
	table, err := cfnEC2RouteTable(h).describe(ctx, id)
	if err != nil {
		return nil, err
	}
	slot := id + "|" + destination
	if err = cfnEC2RelationOwned(ctx, h.commands, r, slot, slot); err != nil {
		return nil, err
	}
	route, exists := cfnEC2RouteFind(table, destination)
	if !exists {
		return nil, cfnEC2NotFound("route")
	}
	return cfnEC2RouteProjection(id, route), nil
}
func (h cfnEC2Route) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	var result []cloudformation.ResourceDescription
	input := map[string]any{}
	if id := cfnComputeString(r.Properties, "RouteTableId"); id != "" {
		input["RouteTableIds"] = []string{id}
	}
	for {
		out, err := cfnComputeCall[api.DescribeRouteTablesResult](ctx, h.commands, "ec2", "DescribeRouteTables", input)
		if err != nil {
			return nil, err
		}
		for _, table := range out.RouteTables {
			id := cfnComputeValue(table.RouteTableId)
			for _, route := range table.Routes {
				if cfnComputeValue(route.Origin) != "CreateRoute" {
					continue
				}
				destination := cfnComputeValue(route.DestinationCidrBlock)
				if destination == "" {
					destination = cfnComputeValue(route.DestinationIpv6CidrBlock)
				}
				if destination == "" {
					continue
				}
				slot := id + "|" + destination
				if !r.CloudControl && cfnEC2RelationOwned(ctx, h.commands, r, slot, slot) != nil {
					continue
				}
				result = append(result, cloudformation.ResourceDescription{Identifier: cfnEC2PairID(r, id, destination, "RouteTableId", "CidrBlock"), Properties: cfnEC2RouteProjection(id, route)})
			}
		}
		if cfnComputeValue(out.NextToken) == "" {
			return result, nil
		}
		input["NextToken"] = cfnComputeValue(out.NextToken)
	}
}
func (h cfnEC2Route) RecoverCreation(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	admitted, _, receiptErr := cfnEC2RelationReceipt(ctx, h.commands, r, "")
	result := cfnEC2IDResult("")
	if admitted != "" {
		parent, cidr, e := cfnEC2Pair(admitted, "RouteTableId", "CidrBlock")
		if e == nil {
			result = cfnEC2IDResult(cfnEC2PairID(r, parent, cidr, "RouteTableId", "CidrBlock"))
		}
	}
	if receiptErr != nil && !errors.Is(receiptErr, ec2.ErrNotFound) {
		return result, receiptErr
	}
	id := cfnComputeString(r.Properties, "RouteTableId")
	destination, err := cfnEC2RouteDestination(r.Properties)
	if err != nil {
		return result, err
	}
	slot := id + "|" + destination
	table, err := cfnEC2RouteTable(h).describe(ctx, id)
	if err != nil {
		return result, fmt.Errorf("cannot observe exact route table during recovery: %v", err)
	}
	liveID := ""
	if _, exists := cfnEC2RouteFind(table, destination); exists {
		liveID = slot
	}
	recovered, err := cfnEC2RelationRecover(ctx, h.commands, r, slot, liveID)
	if recovered.PhysicalID != "" {
		parent, cidr, e := cfnEC2Pair(recovered.PhysicalID, "RouteTableId", "CidrBlock")
		if e != nil {
			return result, e
		}
		result = cfnEC2IDResult(cfnEC2PairID(r, parent, cidr, "RouteTableId", "CidrBlock"))
	} else {
		result = recovered
	}
	return result, err
}
func (h cfnEC2RouteTable) RecoverCreation(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	id, err := cfnEC2NativeRecover(ctx, h.commands, r)
	result := cfnEC2IDResult(id)
	if id != "" {
		result.Attributes = map[string]any{"RouteTableId": id}
	}
	return result, err
}
