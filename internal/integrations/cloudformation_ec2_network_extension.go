package integrations

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	api "stackd/internal/awsapi/ec2"
	"stackd/internal/services/cloudformation"
)

// These adapters use real EC2 control owners; they never imply a NAT guest or
// service packet runtime. Managed interfaces and routes remain ordinary EC2 state.
// Creation and replay use private typed native receipts, never public tag claims.
// Tags, including stackd:cloudformation keys, are customer metadata only.
func CloudFormationEC2NetworkExtensionHandlers(c StepFunctionsCommands) map[string]cloudformation.ResourceHandler {
	return map[string]cloudformation.ResourceHandler{"AWS::EC2::NatGateway": cfnEC2NatGateway{c}, "AWS::EC2::VPCEndpoint": cfnEC2VPCEndpoint{c}}
}
func cfnNetworkToken(r cloudformation.ResourceRequest) string {
	return cfnComputeHash(r.StackID + "/" + r.LogicalID + "/" + r.Type + "/" + r.Token)
}
func cfnNetworkLists(p cloudformation.Properties, keys ...string) error {
	for _, key := range keys {
		if _, err := cfnComputeStringList(p, key); err != nil {
			return err
		}
	}
	return nil
}
func cfnNetworkInteger(p cloudformation.Properties, key string, minimum, maximum int) (int, error) {
	value, ok := p[key]
	if !ok {
		return 0, nil
	}
	var n float64
	switch v := value.(type) {
	case int:
		n = float64(v)
	case int32:
		n = float64(v)
	case int64:
		n = float64(v)
	case float64:
		n = v
	case json.Number:
		var err error
		n, err = v.Float64()
		if err != nil {
			return 0, fmt.Errorf("%s must be an integer", key)
		}
	default:
		return 0, fmt.Errorf("%s must be an integer", key)
	}
	if n != float64(int(n)) || n < float64(minimum) || n > float64(maximum) {
		return 0, fmt.Errorf("%s must be an integer between %d and %d", key, minimum, maximum)
	}
	return int(n), nil
}
func cfnNetworkStrings[S ~[]E, E ~string](values S) []string {
	out := make([]string, len(values))
	for i, v := range values {
		out[i] = string(v)
	}
	return out
}
func cfnNetworkDifference(a, b []string) []string {
	out := []string{}
	for _, id := range a {
		if !slices.Contains(b, id) {
			out = append(out, id)
		}
	}
	return out
}

type cfnEC2NatGateway struct{ commands StepFunctionsCommands }

func (h cfnEC2NatGateway) Validate(p cloudformation.Properties) error {
	if err := cfnComputeProperties(p, "SubnetId", "ConnectivityType", "PrivateIpAddress", "AllocationId", "SecondaryAllocationIds", "SecondaryPrivateIpAddresses", "SecondaryPrivateIpAddressCount", "MaxDrainDurationSeconds", "AvailabilityMode", "Tags"); err != nil {
		return err
	}
	if err := cfnComputeRequired(p, "SubnetId"); err != nil {
		return err
	}
	if err := cfnComputeStrings(p, "SubnetId", "ConnectivityType", "PrivateIpAddress", "AllocationId", "AvailabilityMode"); err != nil {
		return err
	}
	kind := cfnComputeString(p, "ConnectivityType")
	if kind == "" {
		kind = "public"
	}
	if kind != "public" && kind != "private" {
		return fmt.Errorf("ConnectivityType must be public or private")
	}
	if kind == "public" && cfnComputeString(p, "AllocationId") == "" {
		return fmt.Errorf("AllocationId is required for public NAT")
	}
	if kind == "private" && p["AllocationId"] != nil {
		return fmt.Errorf("private NAT cannot use AllocationId")
	}
	if mode := cfnComputeString(p, "AvailabilityMode"); mode != "" && mode != "zonal" {
		return fmt.Errorf("only zonal NAT gateway controls are supported")
	}
	if err := cfnNetworkLists(p, "SecondaryAllocationIds", "SecondaryPrivateIpAddresses"); err != nil {
		return err
	}
	count, err := cfnNetworkInteger(p, "SecondaryPrivateIpAddressCount", 1, 7)
	if err != nil {
		return err
	}
	if count != 0 && p["SecondaryPrivateIpAddresses"] != nil {
		return fmt.Errorf("secondary private addresses and count are mutually exclusive")
	}
	if kind == "public" && count != 0 {
		return fmt.Errorf("secondary count is supported for private NAT only")
	}
	if kind == "private" && p["SecondaryAllocationIds"] != nil {
		return fmt.Errorf("private NAT cannot use secondary allocations")
	}
	if _, err = cfnNetworkInteger(p, "MaxDrainDurationSeconds", 1, 4000); err != nil {
		return err
	}
	_, err = cfnEC2NetworkTags(p)
	return err
}
func (h cfnEC2NatGateway) Replacement(a, b cloudformation.Properties) (bool, error) {
	return cfnComputeChanged(a, b, "SubnetId", "ConnectivityType", "AllocationId", "PrivateIpAddress", "AvailabilityMode"), h.Validate(b)
}
func (h cfnEC2NatGateway) describe(ctx context.Context, id string) (api.NatGateway, error) {
	out, err := cfnComputeCall[api.DescribeNatGatewaysResult](ctx, h.commands, "ec2", "DescribeNatGateways", map[string]any{"NatGatewayIds": []string{id}})
	if err != nil {
		return api.NatGateway{}, err
	}
	if len(out.NatGateways) != 1 {
		return api.NatGateway{}, cfnEC2NotFound("NAT gateway")
	}
	return out.NatGateways[0], nil
}
func (h cfnEC2NatGateway) result(v api.NatGateway) cloudformation.ResourceResult {
	id := cfnComputeValue(v.NatGatewayId)
	eni := ""
	if len(v.NatGatewayAddresses) > 0 {
		eni = cfnComputeValue(v.NatGatewayAddresses[0].NetworkInterfaceId)
	}
	return cloudformation.ResourceResult{PhysicalID: id, Ref: id, Attributes: map[string]any{"NatGatewayId": id, "EniId": eni, "RouteTableId": cfnComputeValue(v.RouteTableId), "AutoProvisionZones": cfnComputeValue(v.AutoProvisionZones), "AutoScalingIps": cfnComputeValue(v.AutoScalingIps)}}
}
func (h cfnEC2NatGateway) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	id, err := cfnEC2NativeRecover(ctx, h.commands, r)
	if err != nil {
		return cfnEC2IDResult(id), err
	}
	if id == "" {
		input := cfnComputeCopy(r.Properties, "SubnetId", "ConnectivityType", "PrivateIpAddress", "AllocationId", "SecondaryAllocationIds", "SecondaryPrivateIpAddresses", "SecondaryPrivateIpAddressCount", "AvailabilityMode")
		input["TagSpecifications"] = cfnEC2NetworkTagSpecifications(r, "natgateway")
		input["ClientToken"] = cfnNetworkToken(r)
		out, err := cfnComputeCall[api.CreateNatGatewayResult](cfnEC2NativeContext(ctx, r, "create"), h.commands, "ec2", "CreateNatGateway", input)
		if err != nil {
			return cloudformation.ResourceResult{}, err
		}
		id = cfnComputeValue(out.NatGateway.NatGatewayId)
	}
	v, err := h.describe(ctx, id)
	if err != nil {
		return cfnEC2IDResult(id), err
	}
	if err = cfnEC2NativeOwned(ctx, h.commands, r, cfnComputeValue(v.NatGatewayId)); err != nil {
		return h.result(v), err
	}
	if cfnComputeValue(v.State) == "deleted" {
		return h.result(v), fmt.Errorf("NAT gateway incarnation was deleted")
	}
	return h.result(v), nil
}
func (h cfnEC2NatGateway) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if replacement, err := h.Replacement(r.Previous, r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	} else if replacement {
		return cloudformation.ResourceResult{}, fmt.Errorf("NAT gateway update requires replacement")
	}
	v, err := h.describe(ctx, r.PhysicalID)
	if err != nil {
		return cfnEC2IDResult(r.PhysicalID), err
	}
	result := h.result(v)
	tags := cfnEC2Tags(v.Tags)
	if err = cfnEC2NativeOwned(ctx, h.commands, r, r.PhysicalID); err != nil {
		return result, err
	}
	if cfnComputeValue(v.State) != "available" {
		return result, fmt.Errorf("NAT gateway is not available")
	}
	desiredAlloc, _ := cfnComputeStringList(r.Properties, "SecondaryAllocationIds")
	desiredIPs, _ := cfnComputeStringList(r.Properties, "SecondaryPrivateIpAddresses")
	count, _ := cfnNetworkInteger(r.Properties, "SecondaryPrivateIpAddressCount", 1, 31)
	secondary := []api.NatGatewayAddress{}
	for _, a := range v.NatGatewayAddresses {
		if a.IsPrimary == nil || !bool(*a.IsPrimary) {
			secondary = append(secondary, a)
		}
	}
	drain := cfnComputeCopy(r.Properties, "MaxDrainDurationSeconds")
	drain["NatGatewayId"] = r.PhysicalID
	if cfnComputeValue(v.ConnectivityType) == "public" {
		remove := []string{}
		present := []string{}
		for _, a := range secondary {
			allocation := cfnComputeValue(a.AllocationId)
			index := slices.Index(desiredAlloc, allocation)
			keep := index >= 0 && (len(desiredIPs) == 0 || index < len(desiredIPs) && desiredIPs[index] == cfnComputeValue(a.PrivateIp))
			if keep {
				present = append(present, allocation)
			} else {
				remove = append(remove, cfnComputeValue(a.AssociationId))
			}
		}
		if len(remove) > 0 {
			input := cfnComputeCopy(drain, "NatGatewayId", "MaxDrainDurationSeconds")
			input["AssociationIds"] = remove
			if err = cfnComputeRun(cfnEC2NativeContext(ctx, r, "mutate"), h.commands, "ec2", "DisassociateNatGatewayAddress", input); err != nil {
				return result, err
			}
		}
		add := cfnNetworkDifference(desiredAlloc, present)
		if len(add) > 0 {
			input := map[string]any{"NatGatewayId": r.PhysicalID, "AllocationIds": add}
			if len(desiredIPs) > 0 {
				ips := []string{}
				for _, allocation := range add {
					index := slices.Index(desiredAlloc, allocation)
					if index >= len(desiredIPs) {
						return result, fmt.Errorf("secondary private addresses must match allocations")
					}
					ips = append(ips, desiredIPs[index])
				}
				input["PrivateIpAddresses"] = ips
			}
			if err = cfnComputeRun(cfnEC2NativeContext(ctx, r, "mutate"), h.commands, "ec2", "AssociateNatGatewayAddress", input); err != nil {
				return result, err
			}
		}
	} else {
		present := []string{}
		for _, a := range secondary {
			present = append(present, cfnComputeValue(a.PrivateIp))
		}
		remove := []string{}
		add := []string{}
		allocate := 0
		if r.Properties["SecondaryPrivateIpAddressCount"] != nil {
			if count < len(present) {
				remove = append(remove, present[count:]...)
			} else {
				allocate = count - len(present)
			}
		} else {
			remove = cfnNetworkDifference(present, desiredIPs)
			add = cfnNetworkDifference(desiredIPs, present)
		}
		if len(remove) > 0 {
			input := cfnComputeCopy(drain, "NatGatewayId", "MaxDrainDurationSeconds")
			input["PrivateIpAddresses"] = remove
			if err = cfnComputeRun(cfnEC2NativeContext(ctx, r, "mutate"), h.commands, "ec2", "UnassignPrivateNatGatewayAddress", input); err != nil {
				return result, err
			}
		}
		if allocate > 0 || len(add) > 0 {
			input := map[string]any{"NatGatewayId": r.PhysicalID}
			if allocate > 0 {
				input["PrivateIpAddressCount"] = allocate
			} else {
				input["PrivateIpAddresses"] = add
			}
			if err = cfnComputeRun(cfnEC2NativeContext(ctx, r, "mutate"), h.commands, "ec2", "AssignPrivateNatGatewayAddress", input); err != nil {
				return result, err
			}
		}
	}
	if err = cfnEC2NetworkUpdateTags(ctx, h.commands, r, r.PhysicalID, tags); err != nil {
		return result, err
	}
	v, err = h.describe(ctx, r.PhysicalID)
	if err != nil {
		return result, err
	}
	return h.result(v), nil
}
func (h cfnEC2NatGateway) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	v, err := h.describe(ctx, r.PhysicalID)
	if err != nil {
		return cfnEC2Absent(err)
	}
	if err = cfnEC2NativeOwned(ctx, h.commands, r, cfnComputeValue(v.NatGatewayId)); err != nil {
		return err
	}
	return cfnEC2Absent(cfnComputeRun(cfnEC2NativeContext(ctx, r, "mutate"), h.commands, "ec2", "DeleteNatGateway", map[string]any{"NatGatewayId": r.PhysicalID}))
}
func (h cfnEC2NatGateway) projection(v api.NatGateway) cloudformation.Properties {
	p := cloudformation.Properties{"NatGatewayId": cfnComputeValue(v.NatGatewayId), "SubnetId": cfnComputeValue(v.SubnetId), "ConnectivityType": cfnComputeValue(v.ConnectivityType), "AvailabilityMode": cfnComputeValue(v.AvailabilityMode), "Tags": cfnEC2NetworkUserTags(v.Tags)}
	allocations, ips := []string{}, []string{}
	for _, a := range v.NatGatewayAddresses {
		if a.IsPrimary != nil && bool(*a.IsPrimary) {
			p["PrivateIpAddress"] = cfnComputeValue(a.PrivateIp)
			p["EniId"] = cfnComputeValue(a.NetworkInterfaceId)
			if a.AllocationId != nil {
				p["AllocationId"] = cfnComputeValue(a.AllocationId)
			}
		} else {
			ips = append(ips, cfnComputeValue(a.PrivateIp))
			if a.AllocationId != nil {
				allocations = append(allocations, cfnComputeValue(a.AllocationId))
			}
		}
	}
	if len(allocations) > 0 {
		p["SecondaryAllocationIds"] = allocations
	}
	if len(ips) > 0 {
		p["SecondaryPrivateIpAddresses"] = ips
	}
	return p
}
func (h cfnEC2NatGateway) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	v, err := h.describe(ctx, r.PhysicalID)
	if err != nil {
		return nil, err
	}
	if err = cfnEC2NativeOwned(ctx, h.commands, r, cfnComputeValue(v.NatGatewayId)); err != nil {
		return nil, err
	}
	if cfnComputeValue(v.State) == "deleted" {
		return nil, cfnEC2NotFound("NAT gateway")
	}
	return h.projection(v), nil
}
func (h cfnEC2NatGateway) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	result := []cloudformation.ResourceDescription{}
	for input := map[string]any{}; ; {
		out, err := cfnComputeCall[api.DescribeNatGatewaysResult](ctx, h.commands, "ec2", "DescribeNatGateways", input)
		if err != nil {
			return nil, err
		}
		for _, v := range out.NatGateways {
			if cfnComputeValue(v.State) == "deleted" || cfnEC2NativeOwned(ctx, h.commands, r, cfnComputeValue(v.NatGatewayId)) != nil {
				continue
			}
			result = append(result, cloudformation.ResourceDescription{Identifier: cfnComputeValue(v.NatGatewayId), Properties: h.projection(v)})
		}
		if cfnComputeValue(out.NextToken) == "" {
			return result, nil
		}
		input["NextToken"] = cfnComputeValue(out.NextToken)
	}
}
func (h cfnEC2NatGateway) Stabilize(ctx context.Context, r cloudformation.ResourceRequest) (bool, error) {
	v, err := h.describe(ctx, r.PhysicalID)
	if err != nil {
		return false, err
	}
	if err = cfnEC2NativeOwned(ctx, h.commands, r, cfnComputeValue(v.NatGatewayId)); err != nil {
		return false, err
	}
	return cfnComputeValue(v.State) == "available", nil
}
func (h cfnEC2NatGateway) Result(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	v, err := h.describe(ctx, r.PhysicalID)
	if err != nil {
		return cfnEC2IDResult(r.PhysicalID), err
	}
	if err = cfnEC2NativeOwned(ctx, h.commands, r, cfnComputeValue(v.NatGatewayId)); err != nil {
		return cfnEC2IDResult(r.PhysicalID), err
	}
	return h.result(v), nil
}
func (h cfnEC2NatGateway) RecoverCreation(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	id, err := cfnEC2NativeRecover(ctx, h.commands, r)
	result := cfnEC2IDResult(id)
	if err != nil || id == "" {
		if err == nil {
			err = cfnEC2NotFound(r.Type)
		}
		return result, err
	}
	r.PhysicalID = id
	return h.Result(ctx, r)
}
