package integrations

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"

	api "stackd/internal/awsapi/ec2"
	"stackd/internal/services/cloudformation"
	"stackd/internal/services/ec2"
)

// Untaggable edges use private native incarnation claims admitted atomically
// with their effects and checked against authoritative live edges under IAM.
// https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-ec2-networkaclentry.html
// https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-ec2-subnetnetworkaclassociation.html
// https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-ec2-eipassociation.html
// https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-ec2-vpcdhcpoptionsassociation.html
type cfnEC2AncillaryRelation struct {
	commands StepFunctionsCommands
	kind     string
}
type cfnEC2AncillaryEdge struct {
	id, parent, slot string
	tags             map[string]string
	properties       cloudformation.Properties
	defaultEdge      bool
	vpc              string
}

func cfnEC2AncillaryComposite(p map[string]any, keys ...string) string {
	value := cfnComputeCopy(p, keys...)
	body, _ := json.Marshal(value)
	return string(body)
}
func (h cfnEC2AncillaryRelation) Validate(p cloudformation.Properties) error {
	var keys, required []string
	switch h.kind {
	case "NetworkAclEntry":
		keys = []string{"NetworkAclId", "RuleNumber", "Egress", "Protocol", "RuleAction", "CidrBlock", "PortRange", "Icmp"}
		required = []string{"NetworkAclId", "RuleNumber", "Protocol", "RuleAction", "CidrBlock"}
	case "SubnetNetworkAclAssociation":
		keys = []string{"SubnetId", "NetworkAclId"}
		required = keys
	case "VPCDHCPOptionsAssociation":
		keys = []string{"VpcId", "DhcpOptionsId"}
		required = keys
	case "EIPAssociation":
		keys = []string{"AllocationId", "EIP", "InstanceId", "NetworkInterfaceId", "PrivateIpAddress"}
	}
	if err := cfnComputeProperties(p, keys...); err != nil {
		return err
	}
	if err := cfnComputeRequired(p, required...); err != nil {
		return err
	}
	if err := cfnComputeStrings(p, "NetworkAclId", "RuleAction", "CidrBlock", "SubnetId", "VpcId", "DhcpOptionsId", "AllocationId", "EIP", "InstanceId", "NetworkInterfaceId", "PrivateIpAddress"); err != nil {
		return err
	}
	if h.kind == "NetworkAclEntry" {
		if err := cfnEC2Booleans(p, "Egress"); err != nil {
			return err
		}
		for _, key := range []string{"RuleNumber", "Protocol"} {
			if _, err := cfnEC2AncillaryNumber(p[key]); err != nil {
				return fmt.Errorf("%s: %w", key, err)
			}
		}
		for _, key := range []string{"PortRange", "Icmp"} {
			if value, ok := p[key]; ok {
				obj, ok := cfnComputeObject(value)
				if !ok {
					return fmt.Errorf("%s must be an object", key)
				}
				fields := []string{"From", "To"}
				if key == "Icmp" {
					fields = []string{"Type", "Code"}
				}
				if err := cfnComputeProperties(obj, fields...); err != nil {
					return err
				}
				if err := cfnComputeRequired(obj, fields...); err != nil {
					return err
				}
				for _, field := range fields {
					if _, err := cfnEC2AncillaryNumber(obj[field]); err != nil {
						return fmt.Errorf("%s.%s: %w", key, field, err)
					}
				}
			}
		}
	}
	if h.kind == "EIPAssociation" {
		selectors, targets := 0, 0
		for _, key := range []string{"AllocationId", "EIP"} {
			if cfnComputeString(p, key) != "" {
				selectors++
			}
		}
		for _, key := range []string{"InstanceId", "NetworkInterfaceId"} {
			if cfnComputeString(p, key) != "" {
				targets++
			}
		}
		if selectors != 1 || targets != 1 {
			return fmt.Errorf("specify exactly one AllocationId/EIP and one InstanceId/NetworkInterfaceId")
		}
	}
	return nil
}
func (h cfnEC2AncillaryRelation) Replacement(a, b cloudformation.Properties) (bool, error) {
	if err := h.Validate(b); err != nil {
		return false, err
	}
	switch h.kind {
	case "NetworkAclEntry":
		return cfnComputeChanged(a, b, "NetworkAclId", "RuleNumber") || cfnComputeDefault(a, "Egress", false) != cfnComputeDefault(b, "Egress", false), nil
	case "SubnetNetworkAclAssociation":
		return cfnComputeChanged(a, b, "SubnetId", "NetworkAclId"), nil
	case "VPCDHCPOptionsAssociation":
		return cfnComputeChanged(a, b, "VpcId", "DhcpOptionsId"), nil
	default:
		return cfnComputeChanged(a, b, "AllocationId", "EIP", "InstanceId", "NetworkInterfaceId", "PrivateIpAddress"), nil
	}
}
func cfnEC2AncillaryEntryID(acl string, egress bool, number int64) string {
	return acl + "|" + strconv.FormatBool(egress) + "|" + strconv.FormatInt(number, 10)
}
func cfnEC2AncillaryEntryInput(p map[string]any) map[string]any {
	in := cfnComputeCopy(p, "NetworkAclId", "RuleNumber", "RuleAction", "CidrBlock", "PortRange")
	in["Egress"] = cfnComputeDefault(p, "Egress", false)
	protocol, _ := cfnEC2AncillaryNumber(p["Protocol"])
	in["Protocol"] = strconv.FormatInt(protocol, 10)
	if icmp, ok := p["Icmp"]; ok {
		in["IcmpTypeCode"] = icmp
	}
	return in
}
func (h cfnEC2AncillaryRelation) acls(ctx context.Context) ([]api.NetworkAcl, error) {
	var acls []api.NetworkAcl
	in := map[string]any{}
	for {
		out, err := cfnComputeCall[api.DescribeNetworkAclsResult](ctx, h.commands, "ec2", "DescribeNetworkAcls", in)
		if err != nil {
			return nil, err
		}
		acls = append(acls, out.NetworkAcls...)
		token := cfnComputeValue(out.NextToken)
		if token == "" {
			return acls, nil
		}
		in["NextToken"] = token
	}
}
func (h cfnEC2AncillaryRelation) edges(ctx context.Context) ([]cfnEC2AncillaryEdge, error) {
	var edges []cfnEC2AncillaryEdge
	switch h.kind {
	case "NetworkAclEntry", "SubnetNetworkAclAssociation":
		acls, err := h.acls(ctx)
		if err != nil {
			return nil, err
		}
		for _, acl := range acls {
			id, vpc := cfnComputeValue(acl.NetworkAclId), cfnComputeValue(acl.VpcId)
			if h.kind == "NetworkAclEntry" {
				for _, entry := range acl.Entries {
					if entry.RuleNumber == nil || int64(*entry.RuleNumber) == 32767 {
						continue
					}
					edges = append(edges, cfnEC2AncillaryEntryEdge(acl, entry))
				}
			}
			if h.kind == "SubnetNetworkAclAssociation" {
				for _, association := range acl.Associations {
					subnet := cfnComputeValue(association.SubnetId)
					out, err := cfnComputeCall[api.DescribeSubnetsResult](ctx, h.commands, "ec2", "DescribeSubnets", map[string]any{"SubnetIds": []string{subnet}})
					if err != nil {
						return nil, err
					}
					if len(out.Subnets) != 1 {
						return nil, cfnEC2AncillaryAbsent(subnet)
					}
					physical := cfnComputeValue(association.NetworkAclAssociationId)
					edges = append(edges, cfnEC2AncillaryEdge{id: physical, parent: subnet, slot: subnet, tags: cfnEC2Tags(out.Subnets[0].Tags), properties: cloudformation.Properties{"AssociationId": physical, "SubnetId": subnet, "NetworkAclId": id}, defaultEdge: acl.IsDefault != nil && bool(*acl.IsDefault), vpc: vpc})
				}
			}
		}
	case "EIPAssociation":
		out, err := cfnComputeCall[api.DescribeAddressesResult](ctx, h.commands, "ec2", "DescribeAddresses", map[string]any{})
		if err != nil {
			return nil, err
		}
		for _, address := range out.Addresses {
			if cfnComputeValue(address.AssociationId) == "" || cfnComputeValue(address.AllocationId) == "" {
				continue
			}
			edges = append(edges, cfnEC2AncillaryAddressEdge(address))
		}
	case "VPCDHCPOptionsAssociation":
		in := map[string]any{}
		for {
			out, err := cfnComputeCall[api.DescribeVpcsResult](ctx, h.commands, "ec2", "DescribeVpcs", in)
			if err != nil {
				return nil, err
			}
			for _, vpc := range out.Vpcs {
				id := cfnComputeValue(vpc.VpcId)
				p := cloudformation.Properties{"VpcId": id, "DhcpOptionsId": cfnComputeValue(vpc.DhcpOptionsId)}
				physical := cfnEC2AncillaryComposite(p, "VpcId", "DhcpOptionsId")
				edges = append(edges, cfnEC2AncillaryEdge{id: physical, parent: id, slot: id, tags: cfnEC2Tags(vpc.Tags), properties: p})
			}
			token := cfnComputeValue(out.NextToken)
			if token == "" {
				break
			}
			in["NextToken"] = token
		}
	}
	return edges, nil
}
func (h cfnEC2AncillaryRelation) item(ctx context.Context, r cloudformation.ResourceRequest) (cfnEC2AncillaryEdge, error) {
	if r.PhysicalID == "" {
		return cfnEC2AncillaryEdge{}, fmt.Errorf("EC2 relation lookup requires an admitted physical ID")
	}
	identifier := r.PhysicalID
	if h.kind == "VPCDHCPOptionsAssociation" {
		p, err := cfnEC2AncillaryDecodeIdentifier(identifier)
		if err != nil {
			return cfnEC2AncillaryEdge{}, err
		}
		identifier = cfnEC2AncillaryComposite(p, "VpcId", "DhcpOptionsId")
	}
	edges, err := h.edges(ctx)
	if err != nil {
		return cfnEC2AncillaryEdge{}, err
	}
	for _, edge := range edges {
		if edge.id == identifier {
			if err := cfnEC2RelationOwned(ctx, h.commands, r, edge.slot, edge.id); err != nil {
				return edge, err
			}
			return edge, nil
		}
	}
	return cfnEC2AncillaryEdge{}, cfnEC2AncillaryAbsent(r.PhysicalID)
}
func (h cfnEC2AncillaryRelation) matches(ctx context.Context, r cloudformation.ResourceRequest, edge cfnEC2AncillaryEdge) (bool, error) {
	p := r.Properties
	switch h.kind {
	case "NetworkAclEntry":
		return cfnEC2ComputeEqual(cfnEC2AncillaryEntryInput(edge.properties), cfnEC2AncillaryEntryInput(p)), nil
	case "SubnetNetworkAclAssociation":
		return edge.properties["NetworkAclId"] == p["NetworkAclId"], nil
	case "VPCDHCPOptionsAssociation":
		return edge.properties["DhcpOptionsId"] == p["DhcpOptionsId"], nil
	case "EIPAssociation":
		if eni := cfnComputeString(p, "NetworkInterfaceId"); eni != "" {
			if edge.properties["NetworkInterfaceId"] != eni {
				return false, nil
			}
		} else {
			instance := cfnComputeString(p, "InstanceId")
			if live := cfnComputeString(edge.properties, "InstanceId"); live != "" {
				if live != instance {
					return false, nil
				}
			} else {
				out, err := cfnComputeCall[api.DescribeInstancesResult](ctx, h.commands, "ec2", "DescribeInstances", map[string]any{"InstanceIds": []string{instance}})
				if err != nil {
					return false, err
				}
				found := false
				for _, reservation := range out.Reservations {
					for _, v := range reservation.Instances {
						for _, eni := range v.NetworkInterfaces {
							found = found || cfnComputeValue(eni.NetworkInterfaceId) == cfnComputeString(edge.properties, "NetworkInterfaceId")
						}
					}
				}
				if !found {
					return false, nil
				}
			}
		}
		if ip := cfnComputeString(p, "PrivateIpAddress"); ip != "" && edge.properties["PrivateIpAddress"] != ip {
			return false, nil
		}
		return true, nil
	}
	return false, nil
}
func (h cfnEC2AncillaryRelation) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	id, _, receiptErr := cfnEC2RelationReceipt(ctx, h.commands, r, "")
	if receiptErr != nil && !errors.Is(receiptErr, ec2.ErrNotFound) {
		return cfnEC2IDResult(id), receiptErr
	}
	if err := h.Validate(r.Properties); err != nil {
		return cfnEC2IDResult(id), err
	}
	parent, slot, _, current, err := h.snapshot(ctx, r)
	if err != nil {
		return cfnEC2IDResult(id), err
	}
	if receiptErr == nil {
		result, err := h.RecoverCreation(ctx, r)
		if err != nil {
			return result, err
		}
		matches, err := h.matches(ctx, r, *current)
		if err != nil {
			return result, err
		}
		if !matches {
			return result, fmt.Errorf("the admitted EC2 relation has different properties")
		}
		return result, nil
	}
	if current != nil {
		switch h.kind {
		case "NetworkAclEntry", "EIPAssociation":
			return cloudformation.ResourceResult{}, fmt.Errorf("an independently owned EC2 relation already occupies this slot")
		case "SubnetNetworkAclAssociation":
			if !current.defaultEdge {
				return cloudformation.ResourceResult{}, fmt.Errorf("subnet already has a nondefault ACL association")
			}
		case "VPCDHCPOptionsAssociation":
			if current.properties["DhcpOptionsId"] == r.Properties["DhcpOptionsId"] {
				return cloudformation.ResourceResult{}, fmt.Errorf("an independently owned DHCP association already exists")
			}
		}
	}
	effectCtx := cfnEC2RelationContext(ctx, r, slot)
	switch h.kind {
	case "NetworkAclEntry":
		err = cfnComputeRun(effectCtx, h.commands, "ec2", "CreateNetworkAclEntry", cfnEC2AncillaryEntryInput(r.Properties))
		id = slot
	case "SubnetNetworkAclAssociation":
		out, e := cfnComputeCall[api.ReplaceNetworkAclAssociationResult](effectCtx, h.commands, "ec2", "ReplaceNetworkAclAssociation", map[string]any{"AssociationId": current.id, "NetworkAclId": r.Properties["NetworkAclId"]})
		err = e
		if e == nil {
			id = cfnComputeValue(out.NewAssociationId)
		}
	case "VPCDHCPOptionsAssociation":
		err = cfnComputeRun(effectCtx, h.commands, "ec2", "AssociateDhcpOptions", cfnComputeCopy(r.Properties, "VpcId", "DhcpOptionsId"))
		id = cfnEC2AncillaryComposite(r.Properties, "VpcId", "DhcpOptionsId")
	case "EIPAssociation":
		in := cfnComputeCopy(r.Properties, "InstanceId", "NetworkInterfaceId", "PrivateIpAddress")
		in["AllocationId"] = parent
		in["AllowReassociation"] = false
		out, e := cfnComputeCall[api.AssociateAddressResult](effectCtx, h.commands, "ec2", "AssociateAddress", in)
		err = e
		if e == nil {
			id = cfnComputeValue(out.AssociationId)
		}
	}
	if err != nil {
		return cfnEC2RelationFailedCreate(ctx, h.commands, r, h.RecoverCreation, err)
	}
	return cfnEC2IDResult(id), nil
}
func (h cfnEC2AncillaryRelation) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	replace, err := h.Replacement(r.Previous, r.Properties)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	if replace {
		return cloudformation.ResourceResult{}, fmt.Errorf("EC2 relation update requires replacement")
	}
	edge, err := h.item(ctx, r)
	if err != nil {
		return cfnEC2IDResult(r.PhysicalID), err
	}
	if h.kind == "NetworkAclEntry" {
		effectCtx := ctx
		if !r.CloudControl {
			effectCtx = cfnEC2RelationContext(ctx, r, edge.slot)
		}
		err = cfnComputeRun(effectCtx, h.commands, "ec2", "ReplaceNetworkAclEntry", cfnEC2AncillaryEntryInput(r.Properties))
	}
	return cfnEC2IDResult(r.PhysicalID), err
}
func (h cfnEC2AncillaryRelation) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	if r.PhysicalID == "" {
		return fmt.Errorf("EC2 relation deletion requires an admitted physical ID")
	}
	edge, err := h.item(ctx, r)
	if cfnEC2Missing(err) {
		if r.CloudControl || len(r.Properties) == 0 {
			return nil
		}
		_, slot, _, _, e := h.snapshot(ctx, r)
		if cfnEC2Missing(e) {
			return nil
		}
		if e != nil {
			return e
		}
		id, _, e := cfnEC2RelationReceipt(ctx, h.commands, r, slot)
		if errors.Is(e, ec2.ErrNotFound) {
			return nil
		}
		if e != nil {
			return e
		}
		if id != r.PhysicalID {
			return fmt.Errorf("EC2 relation deletion physical ID differs from its native creation receipt")
		}
		return nil
	}
	if err != nil {
		return err
	}
	effectCtx := cfnEC2RelationDeletionContext(ctx, r, edge.slot)
	switch h.kind {
	case "NetworkAclEntry":
		err = cfnComputeRun(effectCtx, h.commands, "ec2", "DeleteNetworkAclEntry", cfnComputeCopy(edge.properties, "NetworkAclId", "RuleNumber", "Egress"))
	case "EIPAssociation":
		err = cfnComputeRun(effectCtx, h.commands, "ec2", "DisassociateAddress", map[string]any{"AssociationId": edge.id})
	case "VPCDHCPOptionsAssociation":
		err = cfnComputeRun(effectCtx, h.commands, "ec2", "AssociateDhcpOptions", map[string]any{"VpcId": edge.parent, "DhcpOptionsId": "default"})
	case "SubnetNetworkAclAssociation":
		acls, e := h.acls(ctx)
		if e != nil {
			return e
		}
		defaultID := ""
		for _, acl := range acls {
			if cfnComputeValue(acl.VpcId) == edge.vpc && acl.IsDefault != nil && bool(*acl.IsDefault) {
				defaultID = cfnComputeValue(acl.NetworkAclId)
				break
			}
		}
		if defaultID == "" {
			return fmt.Errorf("VPC has no default network ACL")
		}
		err = cfnComputeRun(effectCtx, h.commands, "ec2", "ReplaceNetworkAclAssociation", map[string]any{"AssociationId": edge.id, "NetworkAclId": defaultID})
	}
	if err != nil && !cfnEC2Missing(err) {
		return err
	}
	return nil
}
func (h cfnEC2AncillaryRelation) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	edge, err := h.item(ctx, r)
	return edge.properties, err
}
func (h cfnEC2AncillaryRelation) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	edges, err := h.edges(ctx)
	if err != nil {
		return nil, err
	}
	out := []cloudformation.ResourceDescription{}
	for _, edge := range edges {
		if !r.CloudControl && cfnEC2RelationOwned(ctx, h.commands, r, edge.slot, edge.id) != nil {
			continue
		}
		out = append(out, cloudformation.ResourceDescription{Identifier: edge.id, Properties: edge.properties})
	}
	return out, nil
}
func (h cfnEC2AncillaryRelation) Stabilize(ctx context.Context, r cloudformation.ResourceRequest) (bool, error) {
	_, err := h.item(ctx, r)
	if cfnEC2Missing(err) {
		return false, nil
	}
	return err == nil, err
}
func (h cfnEC2AncillaryRelation) StabilizeDeletion(ctx context.Context, r cloudformation.ResourceRequest) (bool, error) {
	_, err := h.item(ctx, r)
	if cfnEC2Missing(err) {
		return true, nil
	}
	return false, err
}

func cfnEC2AncillaryDecodeIdentifier(identifier string) (map[string]any, error) {
	var p map[string]any
	if err := json.Unmarshal([]byte(identifier), &p); err != nil {
		return nil, fmt.Errorf("invalid composite EC2 identifier: %w", err)
	}
	if p == nil {
		return nil, fmt.Errorf("EC2 identifier must be an object")
	}
	return p, nil
}
func (h cfnEC2AncillaryRelation) Result(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	edge, err := h.item(ctx, r)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	result := cfnEC2IDResult(r.PhysicalID)
	if h.kind == "SubnetNetworkAclAssociation" {
		result.Attributes = map[string]any{"AssociationId": edge.id}
	} else if h.kind != "VPCDHCPOptionsAssociation" {
		result.Attributes = map[string]any{"Id": edge.id}
	}
	return result, nil
}
