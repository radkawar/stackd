package ec2

import (
	"context"
	"errors"
	"strconv"
	"strings"

	api "stackd/internal/awsapi/ec2"
)

func registerSecurityGroups(s *Service) {
	register(s, "CreateSecurityGroup", s.createSecurityGroup)
	register(s, "DescribeSecurityGroups", s.describeSecurityGroups)
	register(s, "DeleteSecurityGroup", s.deleteSecurityGroup)
	register(s, "AuthorizeSecurityGroupIngress", s.authorizeSecurityGroupIngress)
	register(s, "AuthorizeSecurityGroupEgress", s.authorizeSecurityGroupEgress)
	register(s, "RevokeSecurityGroupIngress", s.revokeSecurityGroupIngress)
	register(s, "RevokeSecurityGroupEgress", s.revokeSecurityGroupEgress)
	register(s, "DescribeSecurityGroupRules", s.describeSecurityGroupRules)
	register(s, "UpdateSecurityGroupRuleDescriptionsIngress", s.updateSecurityGroupRuleDescriptionsIngress)
	register(s, "UpdateSecurityGroupRuleDescriptionsEgress", s.updateSecurityGroupRuleDescriptionsEgress)
}

func sgTextValid(value string, description bool) bool {
	if len(value) > 255 {
		return false
	}
	allowed := " ._-:/()#,@[]+=&;{}!$*"
	if description {
		allowed += "?"
	}
	for _, c := range value {
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune(allowed, c) {
			continue
		}
		return false
	}
	return true
}

func loadSecurityGroup(ctx context.Context, tx Reader, id, name string) (SecurityGroupRecord, error) {
	if name != "" {
		return SecurityGroupRecord{}, unsupported("Security group names require default-VPC resolution; specify GroupId")
	}
	if id == "" {
		return SecurityGroupRecord{}, failure("MissingParameter", "The request must contain GroupId")
	}
	group, err := tx.SecurityGroup(key(ctx, id))
	if errors.Is(err, ErrNotFound) {
		return SecurityGroupRecord{}, missing("security-group", id)
	}
	return group, err
}

func (s *Service) createSecurityGroup(ctx context.Context, tx Transaction, in *api.CreateSecurityGroupRequest) (*api.CreateSecurityGroupResult, error) {
	name, description, vpcID := str(in.GroupName), str(in.Description), str(in.VpcId)
	if name == "" || description == "" {
		return nil, failure("MissingParameter", "GroupName and Description are required")
	}
	if !sgTextValid(name, false) || strings.HasPrefix(name, "sg-") || name == "default" || !sgTextValid(description, true) {
		return nil, failure("InvalidParameterValue", "Invalid security group name or description")
	}
	if vpcID == "" {
		return nil, unsupported("Specify VpcId; implicit default VPC selection is not supported")
	}
	tags, err := CreationTags(in.TagSpecifications, "security-group")
	if err != nil {
		return nil, err
	}
	vpc, sharedSubnet, err := s.sharedVPC(ctx, tx, vpcID, "CreateSecurityGroup")
	if err != nil {
		return nil, err
	}
	if err := s.authorizeCreateWith(ctx, "CreateSecurityGroup", "security-group", "*", tags, vpcConditions(vpc.Key.Scope, vpcID)); err != nil {
		return nil, err
	}
	if sharedSubnet.Key.ID == "" {
		if err := s.authorize(ctx, "CreateSecurityGroup", "vpc", vpcID, vpc.Data.Tags); err != nil {
			return nil, err
		}
	} else if err := s.authorizeSharedNetwork(ctx, "CreateSecurityGroup", "vpc", vpc.Key, sharedSubnet, vpcConditions(vpc.Key.Scope, vpcID)); err != nil {
		return nil, err
	}
	if err := dryRun(in.DryRun); err != nil {
		return nil, err
	}
	groups, err := tx.SecurityGroups(scopeFor(ctx))
	if err != nil {
		return nil, err
	}
	for _, group := range groups {
		if str(group.Data.VpcId) == vpcID && str(group.Data.GroupName) == name {
			return nil, failure("InvalidGroup.Duplicate", "The security group '"+name+"' already exists for VPC '"+vpcID+"'")
		}
	}
	group, err := s.newSecurityGroup(ctx, tx, vpc, name, description, tags, false)
	if err != nil {
		return nil, err
	}
	return &api.CreateSecurityGroupResult{GroupId: group.Data.GroupId, SecurityGroupArn: group.Data.SecurityGroupArn, Tags: group.Data.Tags}, nil
}

func (s *Service) newSecurityGroup(ctx context.Context, tx Transaction, vpc VPCRecord, name, description string, tags api.TagList, selfIngress bool) (SecurityGroupRecord, error) {
	scope := scopeFor(ctx)
	id, err := tx.NextID(scope, "sg")
	if err != nil {
		return SecurityGroupRecord{}, err
	}
	group := SecurityGroupRecord{Key: ResourceKey{Scope: scope, ID: id}, VPCOwnerAccountID: vpc.Key.Scope.AccountID, Data: api.SecurityGroup{
		GroupId: new(api.String(id)), GroupName: new(api.String(name)), Description: new(api.String(description)), OwnerId: new(api.String(scope.AccountID)), VpcId: new(api.String(vpc.Key.ID)),
		SecurityGroupArn: new(api.String(resourceARN(scope, "security-group", id))), Tags: tags,
		IpPermissions: api.IpPermissionList{}, IpPermissionsEgress: api.IpPermissionList{},
	}}
	if err := tx.PutSecurityGroup(group); err != nil {
		return SecurityGroupRecord{}, err
	}
	rules := api.SecurityGroupRuleList{{IpProtocol: new(api.String("-1")), FromPort: new(api.Integer(-1)), ToPort: new(api.Integer(-1)), IsEgress: new(api.Boolean(true)), CidrIpv4: new(api.String("0.0.0.0/0"))}}
	if selfIngress {
		rules = append(rules, api.SecurityGroupRule{IpProtocol: new(api.String("-1")), FromPort: new(api.Integer(-1)), ToPort: new(api.Integer(-1)), IsEgress: new(api.Boolean(false)), ReferencedGroupInfo: &api.ReferencedSecurityGroup{GroupId: new(api.String(id)), UserId: new(api.String(scope.AccountID))}})
	}
	for _, rule := range rules {
		if _, err := putNewSecurityGroupRule(tx, group, rule); err != nil {
			return SecurityGroupRecord{}, err
		}
	}
	if err := syncSecurityGroupPermissions(tx, group); err != nil {
		return SecurityGroupRecord{}, err
	}
	return group, nil
}

func validDescribeGroupID(id string) bool {
	if !strings.HasPrefix(id, "sg-") {
		return false
	}
	suffix := strings.TrimPrefix(id, "sg-")
	if len(suffix) != 8 && len(suffix) != 17 {
		return false
	}
	nonzero := false
	for _, c := range suffix {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
		nonzero = nonzero || c != '0'
	}
	return nonzero
}

func (s *Service) describeSecurityGroups(ctx context.Context, tx Transaction, in *api.DescribeSecurityGroupsRequest) (*api.DescribeSecurityGroupsResult, error) {
	if err := s.authorize(ctx, "DescribeSecurityGroups", "", "*", nil); err != nil {
		return nil, err
	}
	if err := dryRun(in.DryRun); err != nil {
		return nil, err
	}
	if len(in.GroupNames) != 0 {
		return nil, unsupported("GroupNames requires default-VPC resolution; specify GroupIds or group-name filters")
	}
	for _, id := range in.GroupIds {
		if !validDescribeGroupID(string(id)) {
			return nil, failure("InvalidGroupId.Malformed", "Invalid id: \""+string(id)+"\"")
		}
	}
	groups, err := s.visibleSecurityGroups(ctx, tx)
	if err != nil {
		return nil, err
	}
	items := make([]pageItem, 0, len(groups))
	byID := make(map[string]api.SecurityGroup, len(groups))
	for _, group := range groups {
		d := group.Data
		fields := map[string][]string{"group-id": {group.Key.ID}, "group-name": {str(d.GroupName)}, "description": {str(d.Description)}, "owner-id": {str(d.OwnerId)}, "vpc-id": {str(d.VpcId)}}
		sgPermissionFields(fields, "ip-permission.", d.IpPermissions)
		sgPermissionFields(fields, "egress.ip-permission.", d.IpPermissionsEgress)
		items = append(items, pageItem{ID: group.Key.ID, Tags: d.Tags, Fields: fields})
		byID[group.Key.ID] = d
	}
	ids, next, err := selectPage(ctx, "DescribeSecurityGroups", stringsOf(in.GroupIds), in.Filters, maxResults(in.MaxResults), in.NextToken, items)
	if err != nil {
		return nil, err
	}
	out := &api.DescribeSecurityGroupsResult{NextToken: next, SecurityGroups: api.SecurityGroupList{}}
	for _, id := range ids {
		out.SecurityGroups = append(out.SecurityGroups, byID[id])
	}
	return out, nil
}

func sgPermissionFields(fields map[string][]string, prefix string, permissions api.IpPermissionList) {
	for _, suffix := range []string{"from-port", "to-port", "protocol", "cidr", "ipv6-cidr", "group-id", "group-name", "user-id"} {
		fields[prefix+suffix] = nil
	}
	for _, permission := range permissions {
		fields[prefix+"protocol"] = append(fields[prefix+"protocol"], str(permission.IpProtocol))
		if permission.FromPort != nil {
			fields[prefix+"from-port"] = append(fields[prefix+"from-port"], strconv.Itoa(int(*permission.FromPort)))
		}
		if permission.ToPort != nil {
			fields[prefix+"to-port"] = append(fields[prefix+"to-port"], strconv.Itoa(int(*permission.ToPort)))
		}
		for _, r := range permission.IpRanges {
			fields[prefix+"cidr"] = append(fields[prefix+"cidr"], str(r.CidrIp))
		}
		for _, r := range permission.Ipv6Ranges {
			fields[prefix+"ipv6-cidr"] = append(fields[prefix+"ipv6-cidr"], str(r.CidrIpv6))
		}
		for _, r := range permission.UserIdGroupPairs {
			fields[prefix+"group-id"] = append(fields[prefix+"group-id"], str(r.GroupId))
			fields[prefix+"group-name"] = append(fields[prefix+"group-name"], str(r.GroupName))
			fields[prefix+"user-id"] = append(fields[prefix+"user-id"], str(r.UserId))
		}
	}
}

func (s *Service) deleteSecurityGroup(ctx context.Context, tx Transaction, in *api.DeleteSecurityGroupRequest) (*api.DeleteSecurityGroupResult, error) {
	group, err := loadSecurityGroup(ctx, tx, str(in.GroupId), str(in.GroupName))
	if err != nil {
		return nil, err
	}
	if err := s.authorizeWith(ctx, "DeleteSecurityGroup", "security-group", group.Key.ID, group.Data.Tags, vpcConditions(groupVPCScope(group), str(group.Data.VpcId))); err != nil {
		return nil, err
	}
	if err := dryRun(in.DryRun); err != nil {
		return nil, err
	}
	if str(group.Data.GroupName) == "default" {
		return nil, failure("CannotDelete", "The default security group cannot be deleted")
	}
	interfaces, err := tx.NetworkInterfaces(group.Key.Scope)
	if err != nil {
		return nil, err
	}
	for _, network := range interfaces {
		for _, attached := range network.Data.Groups {
			if str(attached.GroupId) == group.Key.ID {
				return nil, failure("DependencyViolation", "resource "+group.Key.ID+" has a dependent object")
			}
		}
	}
	rules, err := tx.SecurityGroupRules(scopeFor(ctx))
	if err != nil {
		return nil, err
	}
	groups, err := tx.RegionalSecurityGroups(group.Key.Scope)
	if err != nil {
		return nil, err
	}
	for _, other := range groups {
		if other.Key == group.Key || groupVPCScope(other) != groupVPCScope(group) || str(other.Data.VpcId) != str(group.Data.VpcId) {
			continue
		}
		for _, permissions := range []api.IpPermissionList{other.Data.IpPermissions, other.Data.IpPermissionsEgress} {
			for _, permission := range permissions {
				for _, reference := range permission.UserIdGroupPairs {
					if str(reference.GroupId) == group.Key.ID && (reference.UserId == nil || str(reference.UserId) == group.Key.Scope.AccountID) {
						return nil, failure("DependencyViolation", "The security group is referenced by another group in this VPC.")
					}
				}
			}
		}
	}
	for _, rule := range rules {
		if str(rule.Data.GroupId) == group.Key.ID {
			if err := tx.DeleteSecurityGroupRule(rule.Key); err != nil {
				return nil, err
			}
		}
	}
	if err := tx.DeleteSecurityGroup(group.Key); err != nil {
		return nil, err
	}
	return &api.DeleteSecurityGroupResult{GroupId: new(api.SecurityGroupId(group.Key.ID)), Return: new(api.Boolean(true))}, nil
}
