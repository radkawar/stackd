package integrations

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"

	api "stackd/internal/awsapi/ec2"
	"stackd/internal/awswire"
	"stackd/internal/services/cloudformation"
)

// CloudFormationEC2AncillaryHandlers delegates every effect to the EC2 owner.
// Contracts: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/AWS_EC2.html
// Schemas: https://schema.cloudformation.us-east-2.amazonaws.com/CloudformationSchema.zip
func CloudFormationEC2AncillaryHandlers(commands StepFunctionsCommands) map[string]cloudformation.ResourceHandler {
	out := map[string]cloudformation.ResourceHandler{}
	for _, kind := range []string{"NetworkAcl", "NetworkInterface", "EIP", "DHCPOptions"} {
		out["AWS::EC2::"+kind] = cfnEC2AncillaryOwner{commands, kind}
	}
	out["AWS::EC2::SecurityGroup"] = cfnEC2SecurityGroup{commands}
	out["AWS::EC2::SecurityGroupIngress"] = cfnEC2SecurityRule{commands, false}
	out["AWS::EC2::SecurityGroupEgress"] = cfnEC2SecurityRule{commands, true}
	for _, kind := range []string{"NetworkAclEntry", "SubnetNetworkAclAssociation", "EIPAssociation", "VPCDHCPOptionsAssociation"} {
		out["AWS::EC2::"+kind] = cfnEC2AncillaryRelation{commands, kind}
	}
	return out
}

type cfnEC2AncillaryOwner struct {
	commands StepFunctionsCommands
	kind     string
}
type cfnEC2AncillaryItem struct {
	id         string
	tags       map[string]string
	properties cloudformation.Properties
	result     cloudformation.ResourceResult
}

func cfnEC2AncillaryAbsent(id string) error {
	return &awswire.Error{Code: "Resource.NotFound", Message: "EC2 resource " + id + " does not exist"}
}
func cfnEC2AncillaryPrimary(p map[string]any) string {
	if ip := cfnComputeString(p, "PrivateIpAddress"); ip != "" {
		return ip
	}
	list, _ := p["PrivateIpAddresses"].([]any)
	for _, entry := range list {
		address, _ := cfnComputeObject(entry)
		if primary, _ := address["Primary"].(bool); primary {
			return cfnComputeString(address, "PrivateIpAddress")
		}
	}
	return ""
}
func cfnEC2AncillaryNumber(v any) (int64, error) {
	switch n := v.(type) {
	case float64:
		if n == float64(int64(n)) {
			return int64(n), nil
		}
	case int:
		return int64(n), nil
	case int64:
		return n, nil
	}
	return 0, fmt.Errorf("value must be an integer")
}
func (h cfnEC2AncillaryOwner) Validate(p cloudformation.Properties) error {
	var allowed, required []string
	switch h.kind {
	case "NetworkAcl":
		allowed = []string{"VpcId", "Tags"}
		required = []string{"VpcId"}
	case "NetworkInterface":
		allowed = []string{"SubnetId", "Description", "PrivateIpAddress", "PrivateIpAddresses", "SecondaryPrivateIpAddressCount", "GroupSet", "SourceDestCheck", "InterfaceType", "Tags"}
		required = []string{"SubnetId"}
	case "EIP":
		allowed = []string{"Domain", "NetworkBorderGroup", "InstanceId", "PublicIpv4Pool", "Tags"}
		if d := cfnComputeString(p, "Domain"); d != "" && d != "vpc" {
			return fmt.Errorf("domain supports only vpc")
		}
		if pool := cfnComputeString(p, "PublicIpv4Pool"); pool != "" && pool != "amazon" {
			return fmt.Errorf("PublicIpv4Pool supports only amazon")
		}
	case "DHCPOptions":
		allowed = []string{"DomainName", "DomainNameServers", "NetbiosNameServers", "NetbiosNodeType", "NtpServers", "Ipv6AddressPreferredLeaseTime", "Tags"}
	}
	if err := cfnComputeProperties(p, allowed...); err != nil {
		return err
	}
	if err := cfnComputeRequired(p, required...); err != nil {
		return err
	}
	if err := cfnComputeStrings(p, "VpcId", "SubnetId", "Description", "PrivateIpAddress", "InterfaceType", "Domain", "NetworkBorderGroup", "InstanceId", "PublicIpv4Pool", "DomainName"); err != nil {
		return err
	}
	if h.kind == "NetworkInterface" {
		if t := cfnComputeString(p, "InterfaceType"); t != "" && t != "interface" {
			return fmt.Errorf("InterfaceType supports only interface; ENI attachment is not implemented")
		}
		if v, ok := p["SourceDestCheck"]; ok {
			if _, ok := v.(bool); !ok {
				return fmt.Errorf("SourceDestCheck must be boolean")
			}
		}
		if groups, err := cfnComputeStringList(p, "GroupSet"); err != nil {
			return err
		} else if _, present := p["GroupSet"]; present && len(groups) == 0 {
			return fmt.Errorf("GroupSet must contain at least one security group")
		}
		if list, ok := p["PrivateIpAddresses"]; ok {
			a, ok := list.([]any)
			if !ok {
				return fmt.Errorf("PrivateIpAddresses must be a list")
			}
			for _, v := range a {
				o, ok := cfnComputeObject(v)
				if !ok {
					return fmt.Errorf("PrivateIpAddresses entries must be objects")
				}
				if err := cfnComputeProperties(o, "PrivateIpAddress", "Primary"); err != nil {
					return err
				}
				if err := cfnComputeRequired(o, "PrivateIpAddress", "Primary"); err != nil {
					return err
				}
				if err := cfnComputeStrings(o, "PrivateIpAddress"); err != nil {
					return err
				}
				if _, ok := o["Primary"].(bool); !ok {
					return fmt.Errorf("primary must be boolean")
				}
			}
		}
		if p["SecondaryPrivateIpAddressCount"] != nil {
			list, _ := p["PrivateIpAddresses"].([]any)
			for _, v := range list {
				address, _ := cfnComputeObject(v)
				if primary, _ := address["Primary"].(bool); !primary {
					return fmt.Errorf("SecondaryPrivateIpAddressCount and explicit secondary PrivateIpAddresses cannot both be specified")
				}
			}
		}
	}
	for _, key := range []string{"SecondaryPrivateIpAddressCount", "NetbiosNodeType", "Ipv6AddressPreferredLeaseTime"} {
		if v, ok := p[key]; ok {
			if _, err := cfnEC2AncillaryNumber(v); err != nil {
				return fmt.Errorf("%s: %w", key, err)
			}
		}
	}
	if v, present := p["SecondaryPrivateIpAddressCount"]; present {
		n, _ := cfnEC2AncillaryNumber(v)
		if n < 0 || n > 2147483647 {
			return fmt.Errorf("SecondaryPrivateIpAddressCount must be a nonnegative 32-bit integer")
		}
	}
	for _, key := range []string{"DomainNameServers", "NetbiosNameServers", "NtpServers"} {
		if _, err := cfnComputeStringList(p, key); err != nil {
			return err
		}
	}
	if h.kind == "DHCPOptions" && len(cfnEC2DHCPConfigurations(p)) == 0 {
		return fmt.Errorf("at least one DHCP configuration is required by the EC2 owner")
	}
	_, err := cfnEC2NetworkTags(p)
	return err
}
func (h cfnEC2AncillaryOwner) Replacement(a, b cloudformation.Properties) (bool, error) {
	if err := h.Validate(b); err != nil {
		return false, err
	}
	var keys []string
	switch h.kind {
	case "NetworkAcl":
		keys = []string{"VpcId"}
	case "NetworkInterface":
		keys = []string{"SubnetId", "PrivateIpAddress", "InterfaceType"}
		if cfnEC2AncillaryPrimary(a) != cfnEC2AncillaryPrimary(b) {
			return true, nil
		}
	case "EIP":
		keys = []string{"Domain", "NetworkBorderGroup", "PublicIpv4Pool"}
	case "DHCPOptions":
		keys = []string{"DomainName", "DomainNameServers", "NetbiosNameServers", "NetbiosNodeType", "NtpServers", "Ipv6AddressPreferredLeaseTime"}
	}
	return cfnComputeChanged(a, b, keys...), nil
}

var cfnEC2DHCPKeys = []struct{ property, key string }{{"DomainName", "domain-name"}, {"DomainNameServers", "domain-name-servers"}, {"NetbiosNameServers", "netbios-name-servers"}, {"NetbiosNodeType", "netbios-node-type"}, {"NtpServers", "ntp-servers"}, {"Ipv6AddressPreferredLeaseTime", "ipv6-address-preferred-lease-time"}}

func cfnEC2DHCPConfigurations(p map[string]any) []map[string]any {
	var out []map[string]any
	for _, pair := range cfnEC2DHCPKeys {
		v, ok := p[pair.property]
		if !ok {
			continue
		}
		var values any
		switch value := v.(type) {
		case string:
			values = []string{value}
		case []any:
			values = value
		default:
			values = []string{fmt.Sprint(v)}
		}
		out = append(out, map[string]any{"Key": pair.key, "Values": values})
	}
	return out
}
func (h cfnEC2AncillaryOwner) items(ctx context.Context) ([]cfnEC2AncillaryItem, error) {
	var items []cfnEC2AncillaryItem
	input := map[string]any{}
	for {
		var token string
		switch h.kind {
		case "NetworkAcl":
			out, err := cfnComputeCall[api.DescribeNetworkAclsResult](ctx, h.commands, "ec2", "DescribeNetworkAcls", input)
			if err != nil {
				return nil, err
			}
			token = cfnComputeValue(out.NextToken)
			for _, v := range out.NetworkAcls {
				id := cfnComputeValue(v.NetworkAclId)
				items = append(items, cfnEC2AncillaryItem{id, cfnEC2Tags(v.Tags), cloudformation.Properties{"Id": id, "VpcId": cfnComputeValue(v.VpcId), "Tags": cfnEC2NetworkUserTags(v.Tags)}, cloudformation.ResourceResult{PhysicalID: id, Ref: id, Attributes: map[string]any{"Id": id}}})
			}
		case "DHCPOptions":
			out, err := cfnComputeCall[api.DescribeDhcpOptionsResult](ctx, h.commands, "ec2", "DescribeDhcpOptions", input)
			if err != nil {
				return nil, err
			}
			token = cfnComputeValue(out.NextToken)
			for _, v := range out.DhcpOptions {
				id := cfnComputeValue(v.DhcpOptionsId)
				p := cloudformation.Properties{"DhcpOptionsId": id, "Tags": cfnEC2NetworkUserTags(v.Tags)}
				for _, config := range v.DhcpConfigurations {
					for _, pair := range cfnEC2DHCPKeys {
						if cfnComputeValue(config.Key) != pair.key {
							continue
						}
						values := []any{}
						for _, x := range config.Values {
							values = append(values, cfnComputeValue(x.Value))
						}
						switch pair.property {
						case "DomainName":
							if len(values) > 0 {
								p[pair.property] = values[0]
							}
						case "NetbiosNodeType", "Ipv6AddressPreferredLeaseTime":
							if len(values) > 0 {
								n, _ := strconv.ParseInt(values[0].(string), 10, 64)
								p[pair.property] = n
							}
						default:
							p[pair.property] = values
						}
					}
				}
				items = append(items, cfnEC2AncillaryItem{id, cfnEC2Tags(v.Tags), p, cloudformation.ResourceResult{PhysicalID: id, Ref: id, Attributes: map[string]any{"DhcpOptionsId": id}}})
			}
		case "EIP":
			out, err := cfnComputeCall[api.DescribeAddressesResult](ctx, h.commands, "ec2", "DescribeAddresses", input)
			if err != nil {
				return nil, err
			}
			for _, v := range out.Addresses {
				id := cfnComputeValue(v.AllocationId)
				if id == "" {
					continue
				}
				ip := cfnComputeValue(v.PublicIp)
				p := cloudformation.Properties{"AllocationId": id, "PublicIp": ip, "Domain": cfnComputeValue(v.Domain), "NetworkBorderGroup": cfnComputeValue(v.NetworkBorderGroup), "PublicIpv4Pool": cfnComputeValue(v.PublicIpv4Pool), "Tags": cfnEC2NetworkUserTags(v.Tags)}
				if v.InstanceId != nil {
					p["InstanceId"] = cfnComputeValue(v.InstanceId)
				}
				items = append(items, cfnEC2AncillaryItem{id, cfnEC2Tags(v.Tags), p, cloudformation.ResourceResult{PhysicalID: id, Ref: ip, Attributes: map[string]any{"AllocationId": id, "PublicIp": ip}}})
			}
		case "NetworkInterface":
			out, err := cfnComputeCall[api.DescribeNetworkInterfacesResult](ctx, h.commands, "ec2", "DescribeNetworkInterfaces", input)
			if err != nil {
				return nil, err
			}
			token = cfnComputeValue(out.NextToken)
			for _, v := range out.NetworkInterfaces {
				id := cfnComputeValue(v.NetworkInterfaceId)
				groups := []any{}
				for _, g := range v.Groups {
					groups = append(groups, cfnComputeValue(g.GroupId))
				}
				addresses := []any{}
				secondary := []any{}
				for _, a := range v.PrivateIpAddresses {
					primary := a.Primary != nil && bool(*a.Primary)
					ip := cfnComputeValue(a.PrivateIpAddress)
					addresses = append(addresses, map[string]any{"PrivateIpAddress": ip, "Primary": primary})
					if !primary {
						secondary = append(secondary, ip)
					}
				}
				check := v.SourceDestCheck != nil && bool(*v.SourceDestCheck)
				p := cloudformation.Properties{"Id": id, "SubnetId": cfnComputeValue(v.SubnetId), "VpcId": cfnComputeValue(v.VpcId), "Description": cfnComputeValue(v.Description), "PrivateIpAddress": cfnComputeValue(v.PrivateIpAddress), "PrimaryPrivateIpAddress": cfnComputeValue(v.PrivateIpAddress), "PrivateIpAddresses": addresses, "SecondaryPrivateIpAddresses": secondary, "GroupSet": groups, "SourceDestCheck": check, "InterfaceType": cfnComputeValue(v.InterfaceType), "Tags": cfnEC2NetworkUserTags(v.TagSet)}
				items = append(items, cfnEC2AncillaryItem{id, cfnEC2Tags(v.TagSet), p, cloudformation.ResourceResult{PhysicalID: id, Ref: id, Attributes: map[string]any{"Id": id, "PrimaryPrivateIpAddress": p["PrimaryPrivateIpAddress"], "SecondaryPrivateIpAddresses": secondary}}})
			}
		}
		if token == "" {
			return items, nil
		}
		input["NextToken"] = token
	}
}
func (h cfnEC2AncillaryOwner) item(ctx context.Context, r cloudformation.ResourceRequest) (cfnEC2AncillaryItem, error) {
	items, err := h.items(ctx)
	if err != nil {
		return cfnEC2AncillaryItem{}, err
	}
	identifier := r.PhysicalID
	var composite map[string]any
	if h.kind == "EIP" && strings.HasPrefix(identifier, "{") {
		composite, err = cfnEC2AncillaryDecodeIdentifier(identifier)
		if err != nil {
			return cfnEC2AncillaryItem{}, err
		}
		identifier = cfnComputeString(composite, "AllocationId")
		if identifier == "" || cfnComputeString(composite, "PublicIp") == "" {
			return cfnEC2AncillaryItem{}, fmt.Errorf("EIP identifier requires AllocationId and PublicIp")
		}
	}
	for _, item := range items {
		if item.id == identifier || (h.kind == "EIP" && item.result.Ref == identifier) {
			if composite != nil && item.result.Ref != cfnComputeString(composite, "PublicIp") {
				return item, cfnEC2AncillaryAbsent(r.PhysicalID)
			}
			if err := cfnEC2NativeOwned(ctx, h.commands, r, item.id); err != nil {
				return item, err
			}
			return item, nil
		}
	}
	return cfnEC2AncillaryItem{}, cfnEC2AncillaryAbsent(r.PhysicalID)
}
func (h cfnEC2AncillaryOwner) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	id, err := cfnEC2NativeRecover(ctx, h.commands, r)
	if err != nil {
		return cfnEC2IDResult(id), err
	}
	if id != "" {
		r.PhysicalID = id
		item, err := h.item(ctx, r)
		if err != nil {
			return cfnEC2IDResult(id), err
		}
		return h.configure(ctx, r, item)
	}
	switch h.kind {
	case "NetworkAcl":
		in := cfnComputeCopy(r.Properties, "VpcId")
		in["ClientToken"] = cfnComputeHash(r.StackID + "/" + r.LogicalID + "/" + r.Token)
		in["TagSpecifications"] = cfnEC2NetworkTagSpecifications(r, "network-acl")
		out, e := cfnComputeCall[api.CreateNetworkAclResult](cfnEC2NativeContext(ctx, r, "create"), h.commands, "ec2", "CreateNetworkAcl", in)
		if e != nil {
			return cloudformation.ResourceResult{}, e
		}
		id = cfnComputeValue(out.NetworkAcl.NetworkAclId)
	case "DHCPOptions":
		out, e := cfnComputeCall[api.CreateDhcpOptionsResult](cfnEC2NativeContext(ctx, r, "create"), h.commands, "ec2", "CreateDhcpOptions", map[string]any{"DhcpConfigurations": cfnEC2DHCPConfigurations(r.Properties), "TagSpecifications": cfnEC2NetworkTagSpecifications(r, "dhcp-options")})
		if e != nil {
			return cloudformation.ResourceResult{}, e
		}
		id = cfnComputeValue(out.DhcpOptions.DhcpOptionsId)
	case "EIP":
		in := cfnComputeCopy(r.Properties, "Domain", "NetworkBorderGroup", "PublicIpv4Pool")
		in["TagSpecifications"] = cfnEC2NetworkTagSpecifications(r, "elastic-ip")
		out, e := cfnComputeCall[api.AllocateAddressResult](cfnEC2NativeContext(ctx, r, "create"), h.commands, "ec2", "AllocateAddress", in)
		if e != nil {
			return cloudformation.ResourceResult{}, e
		}
		id = cfnComputeValue(out.AllocationId)
	case "NetworkInterface":
		in := cfnComputeCopy(r.Properties, "SubnetId", "Description", "PrivateIpAddress", "PrivateIpAddresses", "SecondaryPrivateIpAddressCount", "InterfaceType")
		if v, ok := r.Properties["GroupSet"]; ok {
			in["Groups"] = v
		}
		in["ClientToken"] = cfnComputeHash(r.StackID + "/" + r.LogicalID + "/" + r.Token)
		in["TagSpecifications"] = cfnEC2NetworkTagSpecifications(r, "network-interface")
		out, e := cfnComputeCall[api.CreateNetworkInterfaceResult](cfnEC2NativeContext(ctx, r, "create"), h.commands, "ec2", "CreateNetworkInterface", in)
		if e != nil {
			return cloudformation.ResourceResult{}, e
		}
		id = cfnComputeValue(out.NetworkInterface.NetworkInterfaceId)
	}
	r.PhysicalID = id
	item, err := h.item(ctx, r)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	return h.configure(ctx, r, item)
}
func (h cfnEC2AncillaryOwner) configure(ctx context.Context, r cloudformation.ResourceRequest, item cfnEC2AncillaryItem) (cloudformation.ResourceResult, error) {
	if h.kind == "NetworkInterface" {
		for _, key := range []string{"Description", "SourceDestCheck", "GroupSet"} {
			value, ok := r.Properties[key]
			if !ok {
				if key == "Description" {
					value = ""
				} else if key == "SourceDestCheck" {
					value = true
				} else if r.Previous["GroupSet"] != nil {
					out, err := cfnComputeCall[api.DescribeSecurityGroupsResult](ctx, h.commands, "ec2", "DescribeSecurityGroups", map[string]any{"Filters": []map[string]any{{"Name": "vpc-id", "Values": []any{item.properties["VpcId"]}}, {"Name": "group-name", "Values": []string{"default"}}}})
					if err != nil {
						return item.result, err
					}
					groups := []string{}
					for _, g := range out.SecurityGroups {
						groups = append(groups, cfnComputeValue(g.GroupId))
					}
					if len(groups) != 1 {
						return item.result, fmt.Errorf("default security group was not found")
					}
					value = groups
				} else {
					continue
				}
			}
			in := map[string]any{"NetworkInterfaceId": item.id}
			if key == "GroupSet" {
				in["Groups"] = value
			} else {
				in[key] = map[string]any{"Value": value}
			}
			if err := cfnComputeRun(cfnEC2NativeTargetContext(ctx, r, "mutate", item.id), h.commands, "ec2", "ModifyNetworkInterfaceAttribute", in); err != nil {
				return item.result, err
			}
		}
		if err := h.addresses(ctx, r, item); err != nil {
			return item.result, err
		}
	}
	if h.kind == "EIP" {
		if err := h.eipAssociation(ctx, r, item); err != nil {
			return item.result, err
		}
	}
	if h.kind == "EIP" && r.CloudControl {
		item.result.PhysicalID = cfnEC2AncillaryComposite(item.properties, "PublicIp", "AllocationId")
	}
	return item.result, nil
}
func (h cfnEC2AncillaryOwner) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	replace, err := h.Replacement(r.Previous, r.Properties)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	if replace {
		return cloudformation.ResourceResult{}, fmt.Errorf("EC2 %s update requires replacement", h.kind)
	}
	item, err := h.item(ctx, r)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	result, err := h.configure(ctx, r, item)
	if err != nil {
		return result, err
	}
	return result, cfnEC2NetworkUpdateTags(ctx, h.commands, r, item.id, item.tags)
}
func (h cfnEC2AncillaryOwner) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	item, err := h.item(ctx, r)
	if cfnEC2Missing(err) {
		return nil
	}
	if err != nil {
		return err
	}
	operation, key := "", ""
	switch h.kind {
	case "NetworkAcl":
		operation, key = "DeleteNetworkAcl", "NetworkAclId"
	case "DHCPOptions":
		operation, key = "DeleteDhcpOptions", "DhcpOptionsId"
	case "NetworkInterface":
		operation, key = "DeleteNetworkInterface", "NetworkInterfaceId"
	case "EIP":
		operation, key = "ReleaseAddress", "AllocationId"
		if r.CloudControl || cfnComputeString(r.Properties, "InstanceId") != "" {
			out, err := cfnComputeCall[api.DescribeAddressesResult](ctx, h.commands, "ec2", "DescribeAddresses", map[string]any{"AllocationIds": []string{item.id}})
			if err != nil {
				return err
			}
			for _, address := range out.Addresses {
				if address.AssociationId != nil {
					if !r.CloudControl && cfnComputeValue(address.InstanceId) != cfnComputeString(r.Properties, "InstanceId") {
						return fmt.Errorf("elastic IP association no longer targets this resource's configured instance")
					}
					if err := cfnComputeRun(cfnEC2NativeTargetContext(ctx, r, "mutate", item.id), h.commands, "ec2", "DisassociateAddress", map[string]any{"AssociationId": cfnComputeValue(address.AssociationId)}); err != nil {
						return err
					}
				}
			}
		}
	}
	err = cfnComputeRun(cfnEC2NativeTargetContext(ctx, r, "mutate", item.id), h.commands, "ec2", operation, map[string]any{key: item.id})
	if cfnEC2Missing(err) {
		return nil
	}
	return err
}
func (h cfnEC2AncillaryOwner) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	item, err := h.item(ctx, r)
	return item.properties, err
}
func (h cfnEC2AncillaryOwner) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	items, err := h.items(ctx)
	if err != nil {
		return nil, err
	}
	out := []cloudformation.ResourceDescription{}
	for _, item := range items {
		if !r.CloudControl && cfnEC2NativeOwned(ctx, h.commands, r, item.id) != nil {
			continue
		}
		id := item.id
		if h.kind == "EIP" && r.CloudControl {
			id = cfnEC2AncillaryComposite(item.properties, "PublicIp", "AllocationId")
		}
		out = append(out, cloudformation.ResourceDescription{Identifier: id, Properties: item.properties})
	}
	return out, nil
}
func (h cfnEC2AncillaryOwner) Stabilize(ctx context.Context, r cloudformation.ResourceRequest) (bool, error) {
	_, err := h.item(ctx, r)
	if cfnEC2Missing(err) {
		return false, nil
	}
	return err == nil, err
}
func (h cfnEC2AncillaryOwner) StabilizeDeletion(ctx context.Context, r cloudformation.ResourceRequest) (bool, error) {
	_, err := h.item(ctx, r)
	if cfnEC2Missing(err) {
		return true, nil
	}
	return false, err
}
func (h cfnEC2AncillaryOwner) addresses(ctx context.Context, r cloudformation.ResourceRequest, item cfnEC2AncillaryItem) error {
	current, _ := item.properties["SecondaryPrivateIpAddresses"].([]any)
	if list, ok := r.Properties["PrivateIpAddresses"].([]any); ok && r.Properties["SecondaryPrivateIpAddressCount"] == nil {
		desired := map[string]bool{}
		for _, v := range list {
			p, _ := cfnComputeObject(v)
			primary, _ := p["Primary"].(bool)
			if !primary {
				desired[cfnComputeString(p, "PrivateIpAddress")] = true
			}
		}
		remove := []string{}
		for _, v := range current {
			ip := v.(string)
			if !desired[ip] {
				remove = append(remove, ip)
			} else {
				delete(desired, ip)
			}
		}
		if len(remove) > 0 {
			if err := cfnComputeRun(cfnEC2NativeTargetContext(ctx, r, "mutate", item.id), h.commands, "ec2", "UnassignPrivateIpAddresses", map[string]any{"NetworkInterfaceId": item.id, "PrivateIpAddresses": remove}); err != nil {
				return err
			}
		}
		add := make([]string, 0, len(desired))
		for ip := range desired {
			add = append(add, ip)
		}
		sort.Strings(add)
		if len(add) > 0 {
			return cfnComputeRun(cfnEC2NativeTargetContext(ctx, r, "mutate", item.id), h.commands, "ec2", "AssignPrivateIpAddresses", map[string]any{"NetworkInterfaceId": item.id, "PrivateIpAddresses": add})
		}
		return nil
	}
	count, ok := r.Properties["SecondaryPrivateIpAddressCount"]
	if !ok {
		if r.Previous["SecondaryPrivateIpAddressCount"] == nil && r.Previous["PrivateIpAddresses"] == nil {
			return nil
		}
		count = int64(0)
	}
	n, _ := cfnEC2AncillaryNumber(count)
	delta := n - int64(len(current))
	if delta > 0 {
		return cfnComputeRun(cfnEC2NativeTargetContext(ctx, r, "mutate", item.id), h.commands, "ec2", "AssignPrivateIpAddresses", map[string]any{"NetworkInterfaceId": item.id, "SecondaryPrivateIpAddressCount": delta})
	}
	if delta < 0 {
		remove := current[n:]
		return cfnComputeRun(cfnEC2NativeTargetContext(ctx, r, "mutate", item.id), h.commands, "ec2", "UnassignPrivateIpAddresses", map[string]any{"NetworkInterfaceId": item.id, "PrivateIpAddresses": remove})
	}
	return nil
}
func (h cfnEC2AncillaryOwner) Result(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	item, err := h.item(ctx, r)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	item.result.PhysicalID = r.PhysicalID
	return item.result, nil
}
func (h cfnEC2AncillaryOwner) eipAssociation(ctx context.Context, r cloudformation.ResourceRequest, item cfnEC2AncillaryItem) error {
	instance, previous := cfnComputeString(r.Properties, "InstanceId"), cfnComputeString(r.Previous, "InstanceId")
	if instance == "" && previous == "" {
		return nil
	}
	out, err := cfnComputeCall[api.DescribeAddressesResult](ctx, h.commands, "ec2", "DescribeAddresses", map[string]any{"AllocationIds": []string{item.id}})
	if err != nil {
		return err
	}
	reassociate := false
	for _, address := range out.Addresses {
		if address.AssociationId == nil {
			continue
		}
		live := cfnComputeValue(address.InstanceId)
		if instance != "" && live == instance {
			continue
		}
		if previous == "" || live != previous {
			return fmt.Errorf("elastic IP has an independently changed association")
		}
		reassociate = true
		if instance == "" {
			return cfnComputeRun(cfnEC2NativeTargetContext(ctx, r, "mutate", item.id), h.commands, "ec2", "DisassociateAddress", map[string]any{"AssociationId": cfnComputeValue(address.AssociationId)})
		}
	}
	if instance == "" {
		return nil
	}
	return cfnComputeRun(cfnEC2NativeTargetContext(ctx, r, "mutate", item.id), h.commands, "ec2", "AssociateAddress", map[string]any{"AllocationId": item.id, "InstanceId": instance, "AllowReassociation": reassociate})
}
func (h cfnEC2AncillaryOwner) RecoverCreation(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	id, err := cfnEC2NativeRecover(ctx, h.commands, r)
	result := cfnEC2IDResult(id)
	if err != nil || id == "" {
		if err == nil {
			err = cfnEC2NotFound(r.Type)
		}
		return result, err
	}
	r.PhysicalID = id
	item, err := h.item(ctx, r)
	if err != nil {
		return result, err
	}
	return h.configure(ctx, r, item)
}
