package integrations

import (
	"context"
	"errors"
	"fmt"
	"strconv"

	api "stackd/internal/awsapi/ec2"
	"stackd/internal/services/cloudformation"
	"stackd/internal/services/ec2"
)

func cfnEC2AncillaryEntryEdge(acl api.NetworkAcl, entry api.NetworkAclEntry) cfnEC2AncillaryEdge {
	id, vpc := cfnComputeValue(acl.NetworkAclId), cfnComputeValue(acl.VpcId)
	number := int64(*entry.RuleNumber)
	egress := entry.Egress != nil && bool(*entry.Egress)
	protocol, _ := strconv.ParseInt(cfnComputeValue(entry.Protocol), 10, 64)
	p := cloudformation.Properties{"NetworkAclId": id, "RuleNumber": number, "Egress": egress, "Protocol": protocol, "RuleAction": cfnComputeValue(entry.RuleAction), "CidrBlock": cfnComputeValue(entry.CidrBlock)}
	if entry.PortRange != nil {
		p["PortRange"] = map[string]any{"From": int64(*entry.PortRange.From), "To": int64(*entry.PortRange.To)}
	}
	if entry.IcmpTypeCode != nil {
		p["Icmp"] = map[string]any{"Type": int64(*entry.IcmpTypeCode.Type), "Code": int64(*entry.IcmpTypeCode.Code)}
	}
	physical := cfnEC2AncillaryEntryID(id, egress, number)
	p["Id"] = physical
	return cfnEC2AncillaryEdge{id: physical, parent: id, slot: physical, tags: cfnEC2Tags(acl.Tags), properties: p, vpc: vpc}
}

func cfnEC2AncillaryAddressEdge(address api.Address) cfnEC2AncillaryEdge {
	id, allocation := cfnComputeValue(address.AssociationId), cfnComputeValue(address.AllocationId)
	p := cloudformation.Properties{"Id": id, "AllocationId": allocation, "NetworkInterfaceId": cfnComputeValue(address.NetworkInterfaceId), "PrivateIpAddress": cfnComputeValue(address.PrivateIpAddress)}
	if address.InstanceId != nil {
		p["InstanceId"] = cfnComputeValue(address.InstanceId)
		delete(p, "NetworkInterfaceId")
	}
	return cfnEC2AncillaryEdge{id: id, parent: allocation, slot: allocation, tags: cfnEC2Tags(address.Tags), properties: p}
}

// snapshot observes only the desired native parent and its exact exclusive slot.
// Absence of a dependency is not a creation nonadmission certificate.
func (h cfnEC2AncillaryRelation) snapshot(ctx context.Context, r cloudformation.ResourceRequest) (parent, slot string, tags map[string]string, current *cfnEC2AncillaryEdge, err error) {
	p := r.Properties
	switch h.kind {
	case "NetworkAclEntry":
		parent = cfnComputeString(p, "NetworkAclId")
		number, e := cfnEC2AncillaryNumber(p["RuleNumber"])
		if e != nil {
			err = e
			return
		}
		egress, _ := cfnComputeDefault(p, "Egress", false).(bool)
		slot = cfnEC2AncillaryEntryID(parent, egress, number)
		out, e := cfnComputeCall[api.DescribeNetworkAclsResult](ctx, h.commands, "ec2", "DescribeNetworkAcls", map[string]any{"NetworkAclIds": []string{parent}})
		if e != nil {
			err = e
			return
		}
		if len(out.NetworkAcls) != 1 {
			err = fmt.Errorf("cannot observe exact network ACL %s", parent)
			return
		}
		acl := out.NetworkAcls[0]
		tags = cfnEC2Tags(acl.Tags)
		for _, entry := range acl.Entries {
			if entry.RuleNumber != nil && int64(*entry.RuleNumber) == number && (entry.Egress != nil && bool(*entry.Egress)) == egress {
				edge := cfnEC2AncillaryEntryEdge(acl, entry)
				current = &edge
				break
			}
		}
	case "EIPAssociation":
		input := map[string]any{}
		if allocation := cfnComputeString(p, "AllocationId"); allocation != "" {
			input["AllocationIds"] = []string{allocation}
		} else if ip := cfnComputeString(p, "EIP"); ip != "" {
			input["PublicIps"] = []string{ip}
		} else {
			err = fmt.Errorf("EIP association recovery requires its exact address")
			return
		}
		out, e := cfnComputeCall[api.DescribeAddressesResult](ctx, h.commands, "ec2", "DescribeAddresses", input)
		if e != nil {
			err = e
			return
		}
		if len(out.Addresses) != 1 {
			err = fmt.Errorf("cannot observe exact elastic address")
			return
		}
		edge := cfnEC2AncillaryAddressEdge(out.Addresses[0])
		parent, slot, tags = edge.parent, edge.slot, edge.tags
		if edge.id != "" {
			current = &edge
		}
	case "VPCDHCPOptionsAssociation":
		parent = cfnComputeString(p, "VpcId")
		slot = parent
		if parent == "" {
			err = fmt.Errorf("DHCP association recovery requires its exact VPC")
			return
		}
		out, e := cfnComputeCall[api.DescribeVpcsResult](ctx, h.commands, "ec2", "DescribeVpcs", map[string]any{"VpcIds": []string{parent}})
		if e != nil {
			err = e
			return
		}
		if len(out.Vpcs) != 1 {
			err = fmt.Errorf("cannot observe exact VPC %s", parent)
			return
		}
		vpc := out.Vpcs[0]
		tags = cfnEC2Tags(vpc.Tags)
		properties := cloudformation.Properties{"VpcId": parent, "DhcpOptionsId": cfnComputeValue(vpc.DhcpOptionsId)}
		edge := cfnEC2AncillaryEdge{id: cfnEC2AncillaryComposite(properties, "VpcId", "DhcpOptionsId"), parent: parent, slot: slot, tags: tags, properties: properties}
		current = &edge
	case "SubnetNetworkAclAssociation":
		parent = cfnComputeString(p, "SubnetId")
		slot = parent
		if parent == "" {
			err = fmt.Errorf("ACL association recovery requires its exact subnet")
			return
		}
		subnet, e := (cfnEC2Subnet{h.commands}).describe(ctx, parent)
		if e != nil {
			err = e
			return
		}
		tags = cfnEC2Tags(subnet.Tags)
		input := map[string]any{"Filters": []map[string]any{{"Name": "association.subnet-id", "Values": []string{parent}}}}
		for {
			out, e := cfnComputeCall[api.DescribeNetworkAclsResult](ctx, h.commands, "ec2", "DescribeNetworkAcls", input)
			if e != nil {
				err = e
				return
			}
			for _, acl := range out.NetworkAcls {
				for _, a := range acl.Associations {
					if cfnComputeValue(a.SubnetId) != parent {
						continue
					}
					if current != nil {
						err = fmt.Errorf("multiple native ACL associations occupy subnet %s", parent)
						return
					}
					id := cfnComputeValue(a.NetworkAclAssociationId)
					edge := cfnEC2AncillaryEdge{id: id, parent: parent, slot: slot, tags: tags, properties: cloudformation.Properties{"AssociationId": id, "SubnetId": parent, "NetworkAclId": cfnComputeValue(acl.NetworkAclId)}, defaultEdge: acl.IsDefault != nil && bool(*acl.IsDefault), vpc: cfnComputeValue(acl.VpcId)}
					current = &edge
				}
			}
			token := cfnComputeValue(out.NextToken)
			if token == "" {
				break
			}
			input["NextToken"] = token
		}
		if current == nil {
			err = fmt.Errorf("cannot observe the exact subnet ACL association")
			return
		}
	default:
		err = fmt.Errorf("unsupported exclusive EC2 relation %s", h.kind)
	}
	return
}

func (h cfnEC2AncillaryRelation) RecoverCreation(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	id, _, receiptErr := cfnEC2RelationReceipt(ctx, h.commands, r, "")
	result := cfnEC2IDResult(id)
	if receiptErr != nil && !errors.Is(receiptErr, ec2.ErrNotFound) {
		return result, receiptErr
	}
	_, slot, _, current, err := h.snapshot(ctx, r)
	if err != nil {
		return result, fmt.Errorf("cannot observe exact native EC2 relation during recovery: %v", err)
	}
	liveID := ""
	if current != nil {
		liveID = current.id
	}
	return cfnEC2RelationRecover(ctx, h.commands, r, slot, liveID)
}
