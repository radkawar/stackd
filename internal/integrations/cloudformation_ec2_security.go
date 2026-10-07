package integrations

import (
	"context"
	"fmt"
	"net/netip"
	"reflect"
	"strings"

	api "stackd/internal/awsapi/ec2"
	"stackd/internal/services/cloudformation"
)

// Security resources follow the official SecurityGroup, SecurityGroupIngress and
// SecurityGroupEgress contracts in the regional CloudFormation schema archive.
// https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-ec2-securitygroup.html
// https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-ec2-securitygroupingress.html
// https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-ec2-securitygroupegress.html
// Ownership is native and type/incarnation-specific. SG creation also owns its
// default egress; inline admission validates that SG owner in the native mutation.
// Tags are customer metadata, never an import or rule-adoption authority.
type cfnEC2SecurityGroup struct{ commands StepFunctionsCommands }
type cfnEC2SecurityRule struct {
	commands StepFunctionsCommands
	egress   bool
}

func cfnEC2SecurityRuleValidate(p map[string]any, egress, inline bool) error {
	keys := []string{"CidrIp", "CidrIpv6", "Description", "FromPort", "ToPort", "IpProtocol"}
	if egress {
		keys = append(keys, "DestinationSecurityGroupId", "DestinationPrefixListId")
	} else {
		keys = append(keys, "SourceSecurityGroupId", "SourceSecurityGroupName", "SourceSecurityGroupOwnerId", "SourcePrefixListId")
	}
	if !inline {
		keys = append(keys, "GroupId")
		if !egress {
			keys = append(keys, "GroupName")
		}
	}
	if err := cfnComputeProperties(p, keys...); err != nil {
		return err
	}
	if err := cfnComputeRequired(p, "IpProtocol"); err != nil {
		return err
	}
	if _, err := cfnComputeScalarString(p, "IpProtocol"); err != nil {
		return err
	}
	if err := cfnComputeStrings(p, "CidrIp", "CidrIpv6", "Description", "DestinationSecurityGroupId", "DestinationPrefixListId", "SourceSecurityGroupId", "SourceSecurityGroupName", "SourceSecurityGroupOwnerId", "SourcePrefixListId", "GroupId", "GroupName"); err != nil {
		return err
	}
	if _, ok := p["SourceSecurityGroupName"]; ok {
		return fmt.Errorf("SourceSecurityGroupName is unsupported by the EC2 security rule owner; use SourceSecurityGroupId")
	}
	for _, key := range []string{"SourcePrefixListId", "DestinationPrefixListId"} {
		if _, ok := p[key]; ok {
			return fmt.Errorf("%s is unsupported by the EC2 security rule owner", key)
		}
	}
	if !inline {
		if cfnComputeString(p, "GroupId") == "" && cfnComputeString(p, "GroupName") == "" {
			return fmt.Errorf("GroupId or GroupName is required")
		}
		if cfnComputeString(p, "GroupId") != "" && cfnComputeString(p, "GroupName") != "" {
			return fmt.Errorf("specify only one of GroupId and GroupName")
		}
	}
	sources := 0
	for _, key := range []string{"CidrIp", "CidrIpv6", "SourceSecurityGroupId", "SourceSecurityGroupName", "DestinationSecurityGroupId"} {
		if cfnComputeString(p, key) != "" {
			sources++
		}
	}
	if sources != 1 {
		return fmt.Errorf("exactly one CIDR or security group source/destination is required")
	}
	for _, key := range []string{"FromPort", "ToPort"} {
		if v, ok := p[key]; ok {
			if _, err := cfnEC2AncillaryNumber(v); err != nil {
				return fmt.Errorf("%s: %w", key, err)
			}
		}
	}
	return nil
}
func cfnEC2SecurityPermission(p map[string]any, egress bool) map[string]any {
	out := cfnComputeCopy(p, "IpProtocol", "FromPort", "ToPort")
	out["IpProtocol"], _ = cfnComputeScalarString(p, "IpProtocol")
	if cidr := cfnComputeString(p, "CidrIp"); cidr != "" {
		out["IpRanges"] = []map[string]any{{"CidrIp": cidr, "Description": cfnComputeDefault(p, "Description", "")}}
	}
	key := "SourceSecurityGroupId"
	if egress {
		key = "DestinationSecurityGroupId"
	}
	if cidr := cfnComputeString(p, "CidrIpv6"); cidr != "" {
		out["Ipv6Ranges"] = []map[string]any{{"CidrIpv6": cidr, "Description": cfnComputeDefault(p, "Description", "")}}
	}
	if id, name := cfnComputeString(p, key), cfnComputeString(p, "SourceSecurityGroupName"); id != "" || name != "" {
		pair := map[string]any{"Description": cfnComputeDefault(p, "Description", "")}
		if id != "" {
			pair["GroupId"] = id
		}
		if name != "" {
			pair["GroupName"] = name
		}
		if owner := cfnComputeString(p, "SourceSecurityGroupOwnerId"); owner != "" {
			pair["UserId"] = owner
		}
		out["UserIdGroupPairs"] = []map[string]any{pair}
	}
	return out
}
func cfnEC2SecurityProtocol(s string) string {
	switch strings.ToLower(s) {
	case "tcp":
		return "6"
	case "udp":
		return "17"
	case "icmp":
		return "1"
	case "icmpv6":
		return "58"
	}
	return s
}
func cfnEC2SecurityRuleIdentity(p map[string]any) map[string]any {
	out := cfnComputeCopy(p, "CidrIp", "CidrIpv6", "SourceSecurityGroupId", "SourceSecurityGroupName", "SourcePrefixListId", "DestinationSecurityGroupId", "DestinationPrefixListId")
	if prefix, err := netip.ParsePrefix(cfnComputeString(p, "CidrIp")); err == nil {
		out["CidrIp"] = prefix.Masked().String()
	}
	text, _ := cfnComputeScalarString(p, "IpProtocol")
	protocol := cfnEC2SecurityProtocol(text)
	out["IpProtocol"] = protocol
	if prefix, err := netip.ParsePrefix(cfnComputeString(p, "CidrIpv6")); err == nil {
		out["CidrIpv6"] = prefix.Masked().String()
	}
	if protocol == "6" || protocol == "17" || protocol == "1" || protocol == "58" {
		for _, key := range []string{"FromPort", "ToPort"} {
			n, _ := cfnEC2AncillaryNumber(p[key])
			out[key] = n
		}
	}
	return out
}
func (h cfnEC2SecurityRule) Validate(p cloudformation.Properties) error {
	return cfnEC2SecurityRuleValidate(p, h.egress, false)
}
func (h cfnEC2SecurityRule) Replacement(a, b cloudformation.Properties) (bool, error) {
	if err := h.Validate(b); err != nil {
		return false, err
	}
	keys := []string{"GroupId", "GroupName", "CidrIp", "CidrIpv6", "FromPort", "ToPort", "IpProtocol", "SourceSecurityGroupId", "SourceSecurityGroupName", "SourceSecurityGroupOwnerId", "SourcePrefixListId", "DestinationSecurityGroupId", "DestinationPrefixListId"}
	return cfnComputeChanged(a, b, keys...), nil
}
func (h cfnEC2SecurityRule) group(ctx context.Context, p map[string]any) (api.SecurityGroup, error) {
	in := map[string]any{}
	if id := cfnComputeString(p, "GroupId"); id != "" {
		in["GroupIds"] = []string{id}
	} else {
		in["GroupNames"] = []string{cfnComputeString(p, "GroupName")}
	}
	out, err := cfnComputeCall[api.DescribeSecurityGroupsResult](ctx, h.commands, "ec2", "DescribeSecurityGroups", in)
	if err != nil {
		return api.SecurityGroup{}, err
	}
	if len(out.SecurityGroups) != 1 {
		return api.SecurityGroup{}, fmt.Errorf("security group selector must resolve exactly one group")
	}
	return out.SecurityGroups[0], nil
}
func (h cfnEC2SecurityRule) rules(ctx context.Context) ([]api.SecurityGroupRule, error) {
	var rules []api.SecurityGroupRule
	in := map[string]any{}
	for {
		out, err := cfnComputeCall[api.DescribeSecurityGroupRulesResult](ctx, h.commands, "ec2", "DescribeSecurityGroupRules", in)
		if err != nil {
			return nil, err
		}
		for _, rule := range out.SecurityGroupRules {
			if rule.IsEgress != nil && bool(*rule.IsEgress) == h.egress {
				rules = append(rules, rule)
			}
		}
		token := cfnComputeValue(out.NextToken)
		if token == "" {
			return rules, nil
		}
		in["NextToken"] = token
	}
}
func (h cfnEC2SecurityRule) projection(rule api.SecurityGroupRule) cloudformation.Properties {
	p := cloudformation.Properties{"Id": cfnComputeValue(rule.SecurityGroupRuleId), "GroupId": cfnComputeValue(rule.GroupId), "IpProtocol": cfnComputeValue(rule.IpProtocol)}
	if rule.FromPort != nil {
		p["FromPort"] = int64(*rule.FromPort)
	}
	if rule.ToPort != nil {
		p["ToPort"] = int64(*rule.ToPort)
	}
	if rule.Description != nil {
		p["Description"] = cfnComputeValue(rule.Description)
	}
	if rule.CidrIpv4 != nil {
		p["CidrIp"] = cfnComputeValue(rule.CidrIpv4)
	}
	if rule.CidrIpv6 != nil {
		p["CidrIpv6"] = cfnComputeValue(rule.CidrIpv6)
	}
	if rule.ReferencedGroupInfo != nil {
		key := "SourceSecurityGroupId"
		if h.egress {
			key = "DestinationSecurityGroupId"
		}
		p[key] = cfnComputeValue(rule.ReferencedGroupInfo.GroupId)
		if !h.egress {
			p["SourceSecurityGroupOwnerId"] = cfnComputeValue(rule.ReferencedGroupInfo.UserId)
		}
	}
	return p
}
func (h cfnEC2SecurityRule) item(ctx context.Context, r cloudformation.ResourceRequest) (api.SecurityGroupRule, error) {
	rules, err := h.rules(ctx)
	if err != nil {
		return api.SecurityGroupRule{}, err
	}
	for _, rule := range rules {
		if cfnComputeValue(rule.SecurityGroupRuleId) == r.PhysicalID {
			if err := cfnEC2NativeOwned(ctx, h.commands, r, r.PhysicalID); err != nil {
				return rule, err
			}
			return rule, nil
		}
	}
	return api.SecurityGroupRule{}, cfnEC2AncillaryAbsent(r.PhysicalID)
}
func (h cfnEC2SecurityRule) operation(verb string) string {
	suffix := "Ingress"
	if h.egress {
		suffix = "Egress"
	}
	return verb + "SecurityGroup" + suffix
}
func (h cfnEC2SecurityRule) authorize(ctx context.Context, r cloudformation.ResourceRequest, groupID string) (string, error) {
	in := map[string]any{"GroupId": groupID, "IpPermissions": []map[string]any{cfnEC2SecurityPermission(r.Properties, h.egress)}, "TagSpecifications": cfnEC2NetworkTagSpecifications(r, "security-group-rule")}
	if h.egress {
		out, err := cfnComputeCall[api.AuthorizeSecurityGroupEgressResult](ctx, h.commands, "ec2", h.operation("Authorize"), in)
		if err != nil {
			return "", err
		}
		if len(out.SecurityGroupRules) != 1 {
			return "", fmt.Errorf("EC2 did not return one security group rule")
		}
		return cfnComputeValue(out.SecurityGroupRules[0].SecurityGroupRuleId), nil
	}
	out, err := cfnComputeCall[api.AuthorizeSecurityGroupIngressResult](ctx, h.commands, "ec2", h.operation("Authorize"), in)
	if err != nil {
		return "", err
	}
	if len(out.SecurityGroupRules) != 1 {
		return "", fmt.Errorf("EC2 did not return one security group rule")
	}
	return cfnComputeValue(out.SecurityGroupRules[0].SecurityGroupRuleId), nil
}
func (h cfnEC2SecurityRule) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	group, err := h.group(ctx, r.Properties)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	id, err := cfnEC2NativeRecover(ctx, h.commands, r)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	if id != "" {
		recovered := r
		recovered.PhysicalID = id
		rule, err := h.item(ctx, recovered)
		if err != nil {
			return cloudformation.ResourceResult{}, err
		}
		if cfnComputeValue(rule.GroupId) != cfnComputeValue(group.GroupId) || !reflect.DeepEqual(cfnEC2SecurityRuleIdentity(r.Properties), cfnEC2SecurityRuleIdentity(h.projection(rule))) {
			return cloudformation.ResourceResult{}, fmt.Errorf("recovered security rule does not match the requested group and permission")
		}
	} else {
		id, err = h.authorize(cfnEC2NativeContext(ctx, r, "create"), r, cfnComputeValue(group.GroupId))
	}
	return cfnEC2IDResult(id), err
}
func (h cfnEC2SecurityRule) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	replace, err := h.Replacement(r.Previous, r.Properties)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	if replace {
		return cloudformation.ResourceResult{}, fmt.Errorf("security rule update requires replacement")
	}
	rule, err := h.item(ctx, r)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	suffix := "Ingress"
	if h.egress {
		suffix = "Egress"
	}
	err = cfnComputeRun(cfnEC2NativeContext(ctx, r, "mutate"), h.commands, "ec2", "UpdateSecurityGroupRuleDescriptions"+suffix, map[string]any{"GroupId": cfnComputeValue(rule.GroupId), "SecurityGroupRuleDescriptions": []map[string]any{{"SecurityGroupRuleId": r.PhysicalID, "Description": cfnComputeDefault(r.Properties, "Description", "")}}})
	return cfnEC2IDResult(r.PhysicalID), err
}
func (h cfnEC2SecurityRule) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	rule, err := h.item(ctx, r)
	if cfnEC2Missing(err) {
		return nil
	}
	if err != nil {
		return err
	}
	err = cfnComputeRun(cfnEC2NativeContext(ctx, r, "mutate"), h.commands, "ec2", h.operation("Revoke"), map[string]any{"GroupId": cfnComputeValue(rule.GroupId), "SecurityGroupRuleIds": []string{r.PhysicalID}})
	return cfnEC2Absent(err)
}
func (h cfnEC2SecurityRule) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	rule, err := h.item(ctx, r)
	if err != nil {
		return nil, err
	}
	return h.projection(rule), nil
}
func (h cfnEC2SecurityRule) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	rules, err := h.rules(ctx)
	if err != nil {
		return nil, err
	}
	out := []cloudformation.ResourceDescription{}
	for _, rule := range rules {
		id := cfnComputeValue(rule.SecurityGroupRuleId)
		if cfnEC2NativeOwned(ctx, h.commands, r, id) != nil {
			continue
		}
		out = append(out, cloudformation.ResourceDescription{Identifier: id, Properties: h.projection(rule)})
	}
	return out, nil
}
func (h cfnEC2SecurityRule) Stabilize(ctx context.Context, r cloudformation.ResourceRequest) (bool, error) {
	_, err := h.item(ctx, r)
	if cfnEC2Missing(err) {
		return false, nil
	}
	return err == nil, err
}
func (h cfnEC2SecurityRule) StabilizeDeletion(ctx context.Context, r cloudformation.ResourceRequest) (bool, error) {
	_, err := h.item(ctx, r)
	if cfnEC2Missing(err) {
		return true, nil
	}
	return false, err
}

func (h cfnEC2SecurityGroup) Validate(p cloudformation.Properties) error {
	if err := cfnComputeProperties(p, "GroupDescription", "GroupName", "VpcId", "SecurityGroupIngress", "SecurityGroupEgress", "Tags"); err != nil {
		return err
	}
	if err := cfnComputeRequired(p, "GroupDescription", "VpcId"); err != nil {
		return err
	}
	if err := cfnComputeStrings(p, "GroupDescription", "GroupName", "VpcId"); err != nil {
		return err
	}
	for _, key := range []string{"SecurityGroupIngress", "SecurityGroupEgress"} {
		if value, ok := p[key]; ok {
			list, ok := value.([]any)
			if !ok {
				return fmt.Errorf("%s must be a list", key)
			}
			for i, entry := range list {
				rule, ok := cfnComputeObject(entry)
				if !ok {
					return fmt.Errorf("%s[%d] must be an object", key, i)
				}
				if err := cfnEC2SecurityRuleValidate(rule, key == "SecurityGroupEgress", true); err != nil {
					return fmt.Errorf("%s[%d]: %w", key, i, err)
				}
			}
		}
	}
	_, err := cfnEC2NetworkTags(p)
	return err
}
func (h cfnEC2SecurityGroup) Replacement(a, b cloudformation.Properties) (bool, error) {
	if err := h.Validate(b); err != nil {
		return false, err
	}
	return cfnComputeChanged(a, b, "GroupDescription", "GroupName", "VpcId"), nil
}
func (h cfnEC2SecurityGroup) groups(ctx context.Context) ([]api.SecurityGroup, error) {
	var groups []api.SecurityGroup
	in := map[string]any{}
	for {
		out, err := cfnComputeCall[api.DescribeSecurityGroupsResult](ctx, h.commands, "ec2", "DescribeSecurityGroups", in)
		if err != nil {
			return nil, err
		}
		groups = append(groups, out.SecurityGroups...)
		token := cfnComputeValue(out.NextToken)
		if token == "" {
			return groups, nil
		}
		in["NextToken"] = token
	}
}
func (h cfnEC2SecurityGroup) item(ctx context.Context, r cloudformation.ResourceRequest) (api.SecurityGroup, error) {
	groups, err := h.groups(ctx)
	if err != nil {
		return api.SecurityGroup{}, err
	}
	for _, g := range groups {
		if cfnComputeValue(g.GroupId) == r.PhysicalID {
			if err := cfnEC2NativeOwned(ctx, h.commands, r, r.PhysicalID); err != nil {
				return g, err
			}
			return g, nil
		}
	}
	return api.SecurityGroup{}, cfnEC2AncillaryAbsent(r.PhysicalID)
}
func cfnEC2SecurityGroupResult(g api.SecurityGroup) cloudformation.ResourceResult {
	id := cfnComputeValue(g.GroupId)
	return cloudformation.ResourceResult{PhysicalID: id, Ref: id, Attributes: map[string]any{"Id": id, "GroupId": id, "VpcId": cfnComputeValue(g.VpcId)}}
}
func (h cfnEC2SecurityGroup) sync(ctx context.Context, r cloudformation.ResourceRequest, g api.SecurityGroup) error {
	ctx = cfnEC2NativeContext(ctx, r, "mutate")
	for _, egress := range []bool{false, true} {
		ruleHandler := cfnEC2SecurityRule{h.commands, egress}
		key := "SecurityGroupIngress"
		if egress {
			key = "SecurityGroupEgress"
		}
		desired, _ := r.Properties[key].([]any)
		rules, err := ruleHandler.rules(ctx)
		if err != nil {
			return err
		}
		if egress {
			_, explicit := r.Properties[key]
			if !explicit {
				if _, previous := r.Previous[key]; !previous {
					continue
				}
				desired = []any{map[string]any{"IpProtocol": "-1", "CidrIp": "0.0.0.0/0"}}
			}
		}
		used := map[string]bool{}
		for _, entry := range desired {
			p := entry.(map[string]any)
			identity := cfnEC2SecurityRuleIdentity(p)
			var match *api.SecurityGroupRule
			for i := range rules {
				rule := &rules[i]
				if cfnComputeValue(rule.GroupId) != cfnComputeValue(g.GroupId) {
					continue
				}
				if reflect.DeepEqual(identity, cfnEC2SecurityRuleIdentity(ruleHandler.projection(*rule))) {
					if err := cfnEC2NativeOwned(ctx, h.commands, r, cfnComputeValue(rule.SecurityGroupRuleId)); err != nil {
						return fmt.Errorf("inline rule conflicts with an independently owned rule: %w", err)
					}
					match = rule
					break
				}
			}
			if match != nil {
				id := cfnComputeValue(match.SecurityGroupRuleId)
				used[id] = true
				if cfnComputeString(p, "Description") != cfnComputeValue(match.Description) {
					suffix := "Ingress"
					if egress {
						suffix = "Egress"
					}
					if err := cfnComputeRun(ctx, h.commands, "ec2", "UpdateSecurityGroupRuleDescriptions"+suffix, map[string]any{"GroupId": cfnComputeValue(g.GroupId), "SecurityGroupRuleDescriptions": []map[string]any{{"SecurityGroupRuleId": id, "Description": cfnComputeDefault(p, "Description", "")}}}); err != nil {
						return err
					}
				}
				continue
			}
			rr := r
			rr.Properties = cloudformation.Properties(p)
			id, err := ruleHandler.authorize(ctx, rr, cfnComputeValue(g.GroupId))
			if err != nil {
				return err
			}
			used[id] = true
		}
		for _, rule := range rules {
			if cfnComputeValue(rule.GroupId) != cfnComputeValue(g.GroupId) {
				continue
			}
			id := cfnComputeValue(rule.SecurityGroupRuleId)
			if used[id] {
				continue
			}
			if cfnEC2NativeOwned(ctx, h.commands, r, id) == nil {
				if err := cfnComputeRun(ctx, h.commands, "ec2", ruleHandler.operation("Revoke"), map[string]any{"GroupId": cfnComputeValue(g.GroupId), "SecurityGroupRuleIds": []string{id}}); err != nil {
					return err
				}
			}
		}
	}
	return nil
}
func (h cfnEC2SecurityGroup) Create(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	if err := h.Validate(r.Properties); err != nil {
		return cloudformation.ResourceResult{}, err
	}
	creation := r
	creation.PhysicalID = ""
	name := cfnComputeName(creation, "GroupName", 255)
	id, err := cfnEC2NativeRecover(ctx, h.commands, r)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	if id == "" {
		out, err := cfnComputeCall[api.CreateSecurityGroupResult](cfnEC2NativeContext(ctx, r, "create"), h.commands, "ec2", "CreateSecurityGroup", map[string]any{"GroupName": name, "Description": r.Properties["GroupDescription"], "VpcId": r.Properties["VpcId"], "TagSpecifications": cfnEC2NetworkTagSpecifications(r, "security-group")})
		if err != nil {
			return cloudformation.ResourceResult{}, err
		}
		id = cfnComputeValue(out.GroupId)
	}
	r.PhysicalID = id
	g, err := h.item(ctx, r)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	if cfnComputeValue(g.VpcId) != cfnComputeString(r.Properties, "VpcId") || cfnComputeValue(g.GroupName) != name || cfnComputeValue(g.Description) != cfnComputeString(r.Properties, "GroupDescription") {
		return cloudformation.ResourceResult{}, fmt.Errorf("recovered security group does not match the requested name, VPC and description")
	}
	return cfnEC2SecurityGroupResult(g), h.sync(ctx, r, g)
}
func (h cfnEC2SecurityGroup) Update(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	replace, err := h.Replacement(r.Previous, r.Properties)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	if replace {
		return cloudformation.ResourceResult{}, fmt.Errorf("security group update requires replacement")
	}
	g, err := h.item(ctx, r)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	result := cfnEC2SecurityGroupResult(g)
	if err := h.sync(ctx, r, g); err != nil {
		return result, err
	}
	return result, cfnEC2NetworkUpdateTags(ctx, h.commands, r, r.PhysicalID, cfnEC2Tags(g.Tags))
}
func (h cfnEC2SecurityGroup) Delete(ctx context.Context, r cloudformation.ResourceRequest) error {
	_, err := h.item(ctx, r)
	if cfnEC2Missing(err) {
		return nil
	}
	if err != nil {
		return err
	}
	return cfnEC2Absent(cfnComputeRun(cfnEC2NativeContext(ctx, r, "mutate"), h.commands, "ec2", "DeleteSecurityGroup", map[string]any{"GroupId": r.PhysicalID}))
}
func (h cfnEC2SecurityGroup) projection(ctx context.Context, g api.SecurityGroup) (cloudformation.Properties, error) {
	id := cfnComputeValue(g.GroupId)
	p := cloudformation.Properties{"Id": id, "GroupId": id, "GroupName": cfnComputeValue(g.GroupName), "GroupDescription": cfnComputeValue(g.Description), "VpcId": cfnComputeValue(g.VpcId), "Tags": cfnEC2NetworkUserTags(g.Tags)}
	for _, egress := range []bool{false, true} {
		rh := cfnEC2SecurityRule{h.commands, egress}
		rules, err := rh.rules(ctx)
		if err != nil {
			return nil, err
		}
		list := []any{}
		for _, rule := range rules {
			if cfnComputeValue(rule.GroupId) != id {
				continue
			}
			rp := rh.projection(rule)
			delete(rp, "Id")
			delete(rp, "GroupId")
			list = append(list, rp)
		}
		key := "SecurityGroupIngress"
		if egress {
			key = "SecurityGroupEgress"
		}
		p[key] = list
	}
	return p, nil
}
func (h cfnEC2SecurityGroup) Read(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.Properties, error) {
	g, err := h.item(ctx, r)
	if err != nil {
		return nil, err
	}
	return h.projection(ctx, g)
}
func (h cfnEC2SecurityGroup) List(ctx context.Context, r cloudformation.ResourceRequest) ([]cloudformation.ResourceDescription, error) {
	groups, err := h.groups(ctx)
	if err != nil {
		return nil, err
	}
	out := []cloudformation.ResourceDescription{}
	for _, g := range groups {
		id := cfnComputeValue(g.GroupId)
		if cfnEC2NativeOwned(ctx, h.commands, r, id) != nil {
			continue
		}
		p, err := h.projection(ctx, g)
		if err != nil {
			return nil, err
		}
		out = append(out, cloudformation.ResourceDescription{Identifier: id, Properties: p})
	}
	return out, nil
}
func (h cfnEC2SecurityGroup) Stabilize(ctx context.Context, r cloudformation.ResourceRequest) (bool, error) {
	_, err := h.item(ctx, r)
	if cfnEC2Missing(err) {
		return false, nil
	}
	return err == nil, err
}
func (h cfnEC2SecurityGroup) StabilizeDeletion(ctx context.Context, r cloudformation.ResourceRequest) (bool, error) {
	_, err := h.item(ctx, r)
	if cfnEC2Missing(err) {
		return true, nil
	}
	return false, err
}
func (h cfnEC2SecurityRule) Result(ctx context.Context, r cloudformation.ResourceRequest) (cloudformation.ResourceResult, error) {
	rule, err := h.item(ctx, r)
	if err != nil {
		return cloudformation.ResourceResult{}, err
	}
	id := cfnComputeValue(rule.SecurityGroupRuleId)
	return cloudformation.ResourceResult{PhysicalID: id, Ref: id, Attributes: map[string]any{"Id": id}}, nil
}
