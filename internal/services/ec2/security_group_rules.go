package ec2

import (
	"context"
	"errors"
	"net/netip"
	"sort"
	"strconv"

	api "stackd/internal/awsapi/ec2"
)

type sgRuleChange struct {
	action             string
	groupID, groupName string
	egress             bool
	dryRun             *api.Boolean
	permissions        api.IpPermissionList
	ids                api.SecurityGroupRuleIdList
	descriptions       api.SecurityGroupRuleDescriptionList
	tags               api.TagSpecificationList
}

func sgLegacyPermissions(permissions api.IpPermissionList, protocol, cidr, sourceName, sourceOwner *api.String, from, to *api.Integer) (api.IpPermissionList, error) {
	if sourceName != nil || sourceOwner != nil {
		return nil, unsupported("Legacy source security group names are not supported; use UserIdGroupPairs with GroupId")
	}
	if protocol == nil && cidr == nil && from == nil && to == nil {
		return permissions, nil
	}
	if len(permissions) != 0 {
		return nil, failure("InvalidParameterCombination", "IpPermissions cannot be combined with legacy rule parameters")
	}
	return api.IpPermissionList{{IpProtocol: protocol, FromPort: from, ToPort: to, IpRanges: api.IpRangeList{{CidrIp: cidr}}}}, nil
}

func (s *Service) authorizeSecurityGroupIngress(ctx context.Context, tx Transaction, in *api.AuthorizeSecurityGroupIngressRequest) (*api.AuthorizeSecurityGroupIngressResult, error) {
	permissions, err := sgLegacyPermissions(in.IpPermissions, in.IpProtocol, in.CidrIp, in.SourceSecurityGroupName, in.SourceSecurityGroupOwnerId, in.FromPort, in.ToPort)
	if err != nil {
		return nil, err
	}
	rules, err := s.addSecurityGroupRules(ctx, tx, sgRuleChange{action: "AuthorizeSecurityGroupIngress", groupID: str(in.GroupId), groupName: str(in.GroupName), permissions: permissions, dryRun: in.DryRun, tags: in.TagSpecifications})
	if err != nil {
		return nil, err
	}
	return &api.AuthorizeSecurityGroupIngressResult{Return: new(api.Boolean(true)), SecurityGroupRules: rules}, nil
}

func (s *Service) authorizeSecurityGroupEgress(ctx context.Context, tx Transaction, in *api.AuthorizeSecurityGroupEgressRequest) (*api.AuthorizeSecurityGroupEgressResult, error) {
	permissions, err := sgLegacyPermissions(in.IpPermissions, in.IpProtocol, in.CidrIp, in.SourceSecurityGroupName, in.SourceSecurityGroupOwnerId, in.FromPort, in.ToPort)
	if err != nil {
		return nil, err
	}
	rules, err := s.addSecurityGroupRules(ctx, tx, sgRuleChange{action: "AuthorizeSecurityGroupEgress", groupID: str(in.GroupId), egress: true, permissions: permissions, dryRun: in.DryRun, tags: in.TagSpecifications})
	if err != nil {
		return nil, err
	}
	return &api.AuthorizeSecurityGroupEgressResult{Return: new(api.Boolean(true)), SecurityGroupRules: rules}, nil
}

func (s *Service) revokeSecurityGroupIngress(ctx context.Context, tx Transaction, in *api.RevokeSecurityGroupIngressRequest) (*api.RevokeSecurityGroupIngressResult, error) {
	permissions, err := sgLegacyPermissions(in.IpPermissions, in.IpProtocol, in.CidrIp, in.SourceSecurityGroupName, in.SourceSecurityGroupOwnerId, in.FromPort, in.ToPort)
	if err != nil {
		return nil, err
	}
	rules, err := s.removeSecurityGroupRules(ctx, tx, sgRuleChange{action: "RevokeSecurityGroupIngress", groupID: str(in.GroupId), groupName: str(in.GroupName), permissions: permissions, ids: in.SecurityGroupRuleIds, dryRun: in.DryRun})
	if err != nil {
		return nil, err
	}
	return &api.RevokeSecurityGroupIngressResult{Return: new(api.Boolean(true)), RevokedSecurityGroupRules: rules}, nil
}

func (s *Service) revokeSecurityGroupEgress(ctx context.Context, tx Transaction, in *api.RevokeSecurityGroupEgressRequest) (*api.RevokeSecurityGroupEgressResult, error) {
	permissions, err := sgLegacyPermissions(in.IpPermissions, in.IpProtocol, in.CidrIp, in.SourceSecurityGroupName, in.SourceSecurityGroupOwnerId, in.FromPort, in.ToPort)
	if err != nil {
		return nil, err
	}
	rules, err := s.removeSecurityGroupRules(ctx, tx, sgRuleChange{action: "RevokeSecurityGroupEgress", groupID: str(in.GroupId), egress: true, permissions: permissions, ids: in.SecurityGroupRuleIds, dryRun: in.DryRun})
	if err != nil {
		return nil, err
	}
	return &api.RevokeSecurityGroupEgressResult{Return: new(api.Boolean(true)), RevokedSecurityGroupRules: rules}, nil
}

func (s *Service) updateSecurityGroupRuleDescriptionsIngress(ctx context.Context, tx Transaction, in *api.UpdateSecurityGroupRuleDescriptionsIngressRequest) (*api.UpdateSecurityGroupRuleDescriptionsIngressResult, error) {
	err := s.updateSecurityGroupRuleDescriptions(ctx, tx, sgRuleChange{action: "UpdateSecurityGroupRuleDescriptionsIngress", groupID: str(in.GroupId), groupName: str(in.GroupName), permissions: in.IpPermissions, descriptions: in.SecurityGroupRuleDescriptions, dryRun: in.DryRun})
	if err != nil {
		return nil, err
	}
	return &api.UpdateSecurityGroupRuleDescriptionsIngressResult{Return: new(api.Boolean(true))}, nil
}

func (s *Service) updateSecurityGroupRuleDescriptionsEgress(ctx context.Context, tx Transaction, in *api.UpdateSecurityGroupRuleDescriptionsEgressRequest) (*api.UpdateSecurityGroupRuleDescriptionsEgressResult, error) {
	err := s.updateSecurityGroupRuleDescriptions(ctx, tx, sgRuleChange{action: "UpdateSecurityGroupRuleDescriptionsEgress", groupID: str(in.GroupId), groupName: str(in.GroupName), egress: true, permissions: in.IpPermissions, descriptions: in.SecurityGroupRuleDescriptions, dryRun: in.DryRun})
	if err != nil {
		return nil, err
	}
	return &api.UpdateSecurityGroupRuleDescriptionsEgressResult{Return: new(api.Boolean(true))}, nil
}

func (s *Service) authorizeRuleChange(ctx context.Context, tx Transaction, change sgRuleChange) (SecurityGroupRecord, api.TagList, error) {
	if change.groupID != "" && !validDescribeGroupID(change.groupID) {
		return SecurityGroupRecord{}, nil, failure("InvalidGroupId.Malformed", "The security-group ID '"+change.groupID+"' is malformed")
	}
	group, err := loadSecurityGroup(ctx, tx, change.groupID, change.groupName)
	if err != nil {
		return group, nil, err
	}
	tags, err := CreationTags(change.tags, "security-group-rule")
	if err != nil {
		return group, nil, err
	}
	conditions := vpcConditions(groupVPCScope(group), str(group.Data.VpcId))
	for _, tag := range tags {
		conditions["aws:RequestTag/"+str(tag.Key)] = []string{str(tag.Value)}
		conditions["aws:TagKeys"] = append(conditions["aws:TagKeys"], str(tag.Key))
	}
	if err := s.authorizeWith(ctx, change.action, "security-group", group.Key.ID, group.Data.Tags, conditions); err != nil {
		return group, nil, err
	}
	if len(tags) != 0 {
		tagConditions := map[string][]string{"ec2:CreateAction": {change.action}, "aws:TagKeys": conditions["aws:TagKeys"]}
		for _, tag := range tags {
			tagConditions["aws:RequestTag/"+str(tag.Key)] = []string{str(tag.Value)}
		}
		if err := s.authorizeWith(ctx, "CreateTags", "security-group-rule", "*", nil, tagConditions); err != nil {
			return group, nil, err
		}
	}
	if err := dryRun(change.dryRun); err != nil {
		return group, nil, err
	}
	return group, tags, nil
}

func sgProtocolPorts(permission api.IpPermission) (string, int32, int32, error) {
	protocol := str(permission.IpProtocol)
	switch protocol {
	case "tcp", "udp", "icmp", "icmpv6", "-1":
	default:
		n, err := strconv.Atoi(protocol)
		if err != nil || n < 0 || n > 255 {
			return "", 0, 0, failure("InvalidParameterValue", "IpProtocol must be tcp, udp, icmp, icmpv6, -1, or a protocol number from 0 to 255")
		}
		protocol = strconv.Itoa(n)
	}
	switch protocol {
	case "6":
		protocol = "tcp"
	case "17":
		protocol = "udp"
	case "1":
		protocol = "icmp"
	case "58":
		protocol = "icmpv6"
	}
	if protocol != "tcp" && protocol != "udp" && protocol != "icmp" && protocol != "icmpv6" {
		return protocol, -1, -1, nil
	}
	if permission.FromPort == nil || permission.ToPort == nil {
		return "", 0, 0, failure("MissingParameter", "FromPort and ToPort are required for this protocol")
	}
	from, to := int32(*permission.FromPort), int32(*permission.ToPort)
	if protocol == "tcp" || protocol == "udp" {
		if from < 0 || to > 65535 || from > to {
			return "", 0, 0, failure("InvalidParameterValue", "TCP and UDP ports must be between 0 and 65535 with FromPort no greater than ToPort")
		}
	} else if from < -1 || from > 255 || to < -1 || to > 255 || from == -1 && to != -1 {
		return "", 0, 0, failure("InvalidParameterValue", "ICMP type and code must be between -1 and 255; all types requires all codes")
	}
	return protocol, from, to, nil
}

func sgCanonicalRange(raw string, ipv6 bool) (string, error) {
	prefix, err := netip.ParsePrefix(raw)
	if err != nil || prefix.Addr().Is4() == ipv6 || prefix.Addr().Is4In6() {
		return "", failure("InvalidParameterValue", "Invalid CIDR block: "+raw)
	}
	return prefix.Masked().String(), nil
}

func normalizeSecurityGroupRules(ctx context.Context, tx Reader, group SecurityGroupRecord, permissions api.IpPermissionList, egress bool) (api.SecurityGroupRuleList, error) {
	if len(permissions) == 0 {
		return nil, failure("MissingParameter", "At least one IP permission is required")
	}
	rules := api.SecurityGroupRuleList{}
	for _, permission := range permissions {
		if len(permission.PrefixListIds) != 0 {
			return nil, unsupported("Prefix-list security group rules are not supported")
		}
		protocol, from, to, err := sgProtocolPorts(permission)
		if err != nil {
			return nil, err
		}
		base := api.SecurityGroupRule{GroupId: new(api.SecurityGroupId(group.Key.ID)), GroupOwnerId: new(api.String(group.Key.Scope.AccountID)), IpProtocol: new(api.String(protocol)), FromPort: new(api.Integer(from)), ToPort: new(api.Integer(to)), IsEgress: new(api.Boolean(egress))}
		start := len(rules)
		for _, ipRange := range permission.IpRanges {
			cidr, err := sgCanonicalRange(str(ipRange.CidrIp), false)
			if err != nil {
				return nil, err
			}
			rule := base
			rule.CidrIpv4 = new(api.String(cidr))
			rule.Description = ipRange.Description
			rules = append(rules, rule)
		}
		for _, ipRange := range permission.Ipv6Ranges {
			cidr, err := sgCanonicalRange(str(ipRange.CidrIpv6), true)
			if err != nil {
				return nil, err
			}
			rule := base
			rule.CidrIpv6 = new(api.String(cidr))
			rule.Description = ipRange.Description
			rules = append(rules, rule)
		}
		for _, pair := range permission.UserIdGroupPairs {
			if pair.GroupName != nil || pair.PeeringStatus != nil || pair.VpcPeeringConnectionId != nil {
				return nil, unsupported("Group-name and peered security group references are not supported")
			}
			scope := group.Key.Scope
			if pair.UserId != nil {
				scope.AccountID = str(pair.UserId)
			}
			referenced, err := tx.SecurityGroup(ResourceKey{Scope: scope, ID: str(pair.GroupId)})
			if errors.Is(err, ErrNotFound) {
				return nil, missing("security-group", str(pair.GroupId))
			}
			if err != nil {
				return nil, err
			}
			if str(referenced.Data.VpcId) != str(group.Data.VpcId) || groupVPCScope(referenced) != groupVPCScope(group) {
				return nil, failure("InvalidGroup.NotFound", "You have specified two resources that belong to different networks.")
			}
			if pair.UserId != nil && str(pair.UserId) != referenced.Key.Scope.AccountID || pair.VpcId != nil && str(pair.VpcId) != str(referenced.Data.VpcId) {
				return nil, failure("InvalidGroup.NotFound", "The referenced security group does not exist in the specified account and VPC")
			}
			rule := base
			rule.ReferencedGroupInfo = &api.ReferencedSecurityGroup{GroupId: new(api.String(referenced.Key.ID)), UserId: new(api.String(referenced.Key.Scope.AccountID))}
			rule.Description = pair.Description
			rules = append(rules, rule)
		}
		if len(rules) == start {
			return nil, failure("MissingParameter", "Each permission requires a CIDR or security group reference")
		}
		for _, rule := range rules[start:] {
			if !sgTextValid(str(rule.Description), true) {
				return nil, failure("InvalidParameterValue", "Invalid security group rule description")
			}
		}
	}
	return rules, nil
}

type sgRuleIdentity struct {
	protocol, ipv4, ipv6, reference string
	from, to                        int32
	egress                          bool
}

func securityGroupRuleIdentity(rule api.SecurityGroupRule) sgRuleIdentity {
	identity := sgRuleIdentity{protocol: str(rule.IpProtocol), ipv4: str(rule.CidrIpv4), ipv6: str(rule.CidrIpv6), from: -1, to: -1, egress: rule.IsEgress != nil && bool(*rule.IsEgress)}
	if rule.FromPort != nil {
		identity.from = int32(*rule.FromPort)
	}
	if rule.ToPort != nil {
		identity.to = int32(*rule.ToPort)
	}
	if rule.ReferencedGroupInfo != nil {
		identity.reference = str(rule.ReferencedGroupInfo.GroupId)
	}
	return identity
}

func putNewSecurityGroupRule(tx Transaction, group SecurityGroupRecord, rule api.SecurityGroupRule) (api.SecurityGroupRule, error) {
	id, err := tx.NextID(group.Key.Scope, "sgr")
	if err != nil {
		return api.SecurityGroupRule{}, err
	}
	rule.GroupId = new(api.SecurityGroupId(group.Key.ID))
	rule.GroupOwnerId = new(api.String(group.Key.Scope.AccountID))
	rule.SecurityGroupRuleId = new(api.SecurityGroupRuleId(id))
	rule.SecurityGroupRuleArn = new(api.String(resourceARN(group.Key.Scope, "security-group-rule", id)))
	if err := tx.PutSecurityGroupRule(SecurityGroupRuleRecord{Key: ResourceKey{Scope: group.Key.Scope, ID: id}, Data: rule}); err != nil {
		return api.SecurityGroupRule{}, err
	}
	return rule, nil
}

func (s *Service) addSecurityGroupRules(ctx context.Context, tx Transaction, change sgRuleChange) (api.SecurityGroupRuleList, error) {
	group, tags, err := s.authorizeRuleChange(ctx, tx, change)
	if err != nil {
		return nil, err
	}
	rules, err := normalizeSecurityGroupRules(ctx, tx, group, change.permissions, change.egress)
	if err != nil {
		return nil, err
	}
	existing, err := tx.SecurityGroupRules(group.Key.Scope)
	if err != nil {
		return nil, err
	}
	identities := make(map[sgRuleIdentity]bool)
	for _, record := range existing {
		if str(record.Data.GroupId) == group.Key.ID {
			identities[securityGroupRuleIdentity(record.Data)] = true
		}
	}
	for _, rule := range rules {
		identity := securityGroupRuleIdentity(rule)
		if identities[identity] {
			return nil, failure("InvalidPermission.Duplicate", "The specified rule already exists in this security group")
		}
		identities[identity] = true
	}
	out := make(api.SecurityGroupRuleList, 0, len(rules))
	for _, rule := range rules {
		rule.Tags = tags
		saved, err := putNewSecurityGroupRule(tx, group, rule)
		if err != nil {
			return nil, err
		}
		out = append(out, saved)
	}
	if err := syncSecurityGroupPermissions(tx, group); err != nil {
		return nil, err
	}
	return out, nil
}

func selectSecurityGroupRules(ctx context.Context, tx Reader, group SecurityGroupRecord, change sgRuleChange) ([]SecurityGroupRuleRecord, api.SecurityGroupRuleList, error) {
	if len(change.ids) != 0 && len(change.permissions) != 0 {
		return nil, nil, failure("InvalidParameterCombination", "Specify rule IDs or IP permissions, not both")
	}
	selected := []SecurityGroupRuleRecord{}
	seen := make(map[string]bool)
	if len(change.ids) != 0 {
		for _, id := range change.ids {
			rule, err := tx.SecurityGroupRule(key(ctx, string(id)))
			if errors.Is(err, ErrNotFound) {
				return nil, nil, missing("security-group-rule", string(id))
			}
			if err != nil {
				return nil, nil, err
			}
			if str(rule.Data.GroupId) != group.Key.ID || (rule.Data.IsEgress != nil && bool(*rule.Data.IsEgress)) != change.egress {
				return nil, nil, failure("InvalidSecurityGroupRuleId.NotFound", "The security group rule ID '"+string(id)+"' does not exist in this group and direction")
			}
			if !seen[rule.Key.ID] {
				selected = append(selected, rule)
				seen[rule.Key.ID] = true
			}
		}
		return selected, nil, nil
	}
	requested, err := normalizeSecurityGroupRules(ctx, tx, group, change.permissions, change.egress)
	if err != nil {
		return nil, nil, err
	}
	existing, err := tx.SecurityGroupRules(group.Key.Scope)
	if err != nil {
		return nil, nil, err
	}
	byIdentity := make(map[sgRuleIdentity]SecurityGroupRuleRecord)
	for _, rule := range existing {
		if str(rule.Data.GroupId) == group.Key.ID {
			byIdentity[securityGroupRuleIdentity(rule.Data)] = rule
		}
	}
	updates := api.SecurityGroupRuleList{}
	for _, wanted := range requested {
		rule, ok := byIdentity[securityGroupRuleIdentity(wanted)]
		if !ok {
			return nil, nil, failure("InvalidPermission.NotFound", "The specified rule does not exist in this security group.")
		}
		if !seen[rule.Key.ID] {
			selected = append(selected, rule)
			updates = append(updates, wanted)
			seen[rule.Key.ID] = true
		}
	}
	return selected, updates, nil
}

func (s *Service) removeSecurityGroupRules(ctx context.Context, tx Transaction, change sgRuleChange) (api.RevokedSecurityGroupRuleList, error) {
	group, _, err := s.authorizeRuleChange(ctx, tx, change)
	if err != nil {
		return nil, err
	}
	selected, _, err := selectSecurityGroupRules(ctx, tx, group, change)
	if err != nil {
		return nil, err
	}
	out := make(api.RevokedSecurityGroupRuleList, 0, len(selected))
	for _, record := range selected {
		rule := record.Data
		revoked := api.RevokedSecurityGroupRule{SecurityGroupRuleId: rule.SecurityGroupRuleId, GroupId: rule.GroupId, IsEgress: rule.IsEgress, IpProtocol: rule.IpProtocol, FromPort: rule.FromPort, ToPort: rule.ToPort, CidrIpv4: rule.CidrIpv4, CidrIpv6: rule.CidrIpv6, Description: rule.Description}
		if rule.ReferencedGroupInfo != nil {
			revoked.ReferencedGroupId = new(api.SecurityGroupId(str(rule.ReferencedGroupInfo.GroupId)))
		}
		out = append(out, revoked)
	}
	for _, record := range selected {
		if err := tx.DeleteSecurityGroupRule(record.Key); err != nil {
			return nil, err
		}
	}
	if err := syncSecurityGroupPermissions(tx, group); err != nil {
		return nil, err
	}
	return out, nil
}

func (s *Service) updateSecurityGroupRuleDescriptions(ctx context.Context, tx Transaction, change sgRuleChange) error {
	group, _, err := s.authorizeRuleChange(ctx, tx, change)
	if err != nil {
		return err
	}
	if len(change.descriptions) != 0 && len(change.permissions) != 0 {
		return failure("InvalidParameterCombination", "Specify rule descriptions or IP permissions, not both")
	}
	descriptions := make(map[string]*api.String, len(change.descriptions))
	for _, description := range change.descriptions {
		id := str(description.SecurityGroupRuleId)
		if id == "" {
			return failure("MissingParameter", "SecurityGroupRuleId is required")
		}
		if !sgTextValid(str(description.Description), true) {
			return failure("InvalidParameterValue", "Invalid security group rule description")
		}
		if _, duplicate := descriptions[id]; duplicate {
			return failure("InvalidParameterValue", "Duplicate security group rule ID")
		}
		change.ids = append(change.ids, api.String(id))
		descriptions[id] = description.Description
	}
	selected, requested, err := selectSecurityGroupRules(ctx, tx, group, change)
	if err != nil {
		return err
	}
	for i, record := range selected {
		if len(change.descriptions) != 0 {
			record.Data.Description = descriptions[record.Key.ID]
		} else {
			record.Data.Description = requested[i].Description
		}
		if str(record.Data.Description) == "" {
			record.Data.Description = nil
		}
		if err := tx.PutSecurityGroupRule(record); err != nil {
			return err
		}
	}
	return syncSecurityGroupPermissions(tx, group)
}

func syncSecurityGroupPermissions(tx Transaction, group SecurityGroupRecord) error {
	rules, err := tx.SecurityGroupRules(group.Key.Scope)
	if err != nil {
		return err
	}
	sort.Slice(rules, func(i, j int) bool { return rules[i].Key.ID < rules[j].Key.ID })
	group.Data.IpPermissions = api.IpPermissionList{}
	group.Data.IpPermissionsEgress = api.IpPermissionList{}
	type permissionKey struct {
		protocol string
		from, to int32
		egress   bool
	}
	indexes := make(map[permissionKey]int)
	for _, record := range rules {
		rule := record.Data
		if str(rule.GroupId) != group.Key.ID {
			continue
		}
		identity := securityGroupRuleIdentity(rule)
		key := permissionKey{identity.protocol, identity.from, identity.to, identity.egress}
		list := &group.Data.IpPermissions
		if identity.egress {
			list = &group.Data.IpPermissionsEgress
		}
		index, exists := indexes[key]
		if !exists {
			permission := api.IpPermission{IpProtocol: rule.IpProtocol, IpRanges: api.IpRangeList{}, Ipv6Ranges: api.Ipv6RangeList{}, UserIdGroupPairs: api.UserIdGroupPairList{}, PrefixListIds: api.PrefixListIdList{}}
			if identity.protocol == "tcp" || identity.protocol == "udp" || identity.protocol == "icmp" || identity.protocol == "icmpv6" {
				permission.FromPort = rule.FromPort
				permission.ToPort = rule.ToPort
			}
			index = len(*list)
			indexes[key] = index
			*list = append(*list, permission)
		}
		permission := &(*list)[index]
		if rule.CidrIpv4 != nil {
			permission.IpRanges = append(permission.IpRanges, api.IpRange{CidrIp: rule.CidrIpv4, Description: rule.Description})
		}
		if rule.CidrIpv6 != nil {
			permission.Ipv6Ranges = append(permission.Ipv6Ranges, api.Ipv6Range{CidrIpv6: rule.CidrIpv6, Description: rule.Description})
		}
		if rule.ReferencedGroupInfo != nil {
			permission.UserIdGroupPairs = append(permission.UserIdGroupPairs, api.UserIdGroupPair{GroupId: rule.ReferencedGroupInfo.GroupId, UserId: rule.ReferencedGroupInfo.UserId, Description: rule.Description})
		}
	}
	return tx.PutSecurityGroup(group)
}

func (s *Service) describeSecurityGroupRules(ctx context.Context, tx Transaction, in *api.DescribeSecurityGroupRulesRequest) (*api.DescribeSecurityGroupRulesResult, error) {
	if err := s.authorize(ctx, "DescribeSecurityGroupRules", "", "*", nil); err != nil {
		return nil, err
	}
	if err := dryRun(in.DryRun); err != nil {
		return nil, err
	}
	records, err := tx.SecurityGroupRules(scopeFor(ctx))
	if err != nil {
		return nil, err
	}
	items := make([]pageItem, 0, len(records))
	byID := make(map[string]api.SecurityGroupRule, len(records))
	for _, record := range records {
		rule := record.Data
		fields := map[string][]string{"security-group-rule-id": {record.Key.ID}, "group-id": {str(rule.GroupId)}, "group-owner-id": {str(rule.GroupOwnerId)}, "is-egress": {strconv.FormatBool(boolValue(rule.IsEgress))}}
		items = append(items, pageItem{ID: record.Key.ID, Tags: rule.Tags, Fields: fields})
		if rule.Tags == nil {
			rule.Tags = api.TagList{}
		}
		byID[record.Key.ID] = rule
	}
	ids, next, err := selectPage(ctx, "DescribeSecurityGroupRules", stringsOf(in.SecurityGroupRuleIds), in.Filters, maxResults(in.MaxResults), in.NextToken, items)
	if err != nil {
		return nil, err
	}
	out := &api.DescribeSecurityGroupRulesResult{NextToken: next, SecurityGroupRules: api.SecurityGroupRuleList{}}
	for _, id := range ids {
		out.SecurityGroupRules = append(out.SecurityGroupRules, byID[id])
	}
	return out, nil
}
