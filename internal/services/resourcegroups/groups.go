package resourcegroups

import (
	"maps"
	"slices"
	"strconv"
	"strings"

	api "stackd/internal/awsapi/resourcegroups"
)

func groupOutput(g Group) *api.Group {
	out := &api.Group{GroupArn: new(api.GroupArnV2(g.ARN)), Name: new(api.GroupName(g.Name))}
	if g.Description != "" {
		out.Description = new(api.Description(g.Description))
	}
	if g.ManagedType == applicationGroupType {
		out.ApplicationTag = api.ApplicationTag{api.ApplicationTagKey(applicationTagKey): api.ApplicationArn(g.ARN)}
		if g.DisplayName != "" {
			out.DisplayName = new(api.DisplayName(g.DisplayName))
		}
		if g.Owner != "" {
			out.Owner = new(api.Owner(g.Owner))
		}
		if g.Criticality != nil {
			out.Criticality = new(api.Criticality(*g.Criticality))
		}
	}
	return out
}
func tagsOutput(tags map[string]string) api.Tags {
	out := api.Tags{}
	for k, v := range tags {
		out[api.TagKey(k)] = api.TagValue(v)
	}
	return out
}
func tagsInput(tags api.Tags) (map[string]string, error) {
	out := make(map[string]string, len(tags))
	for k, v := range tags {
		if strings.HasPrefix(strings.ToLower(string(k)), "aws:") {
			return nil, failure("BadRequestException", "Tag keys beginning with aws: are reserved.")
		}
		out[string(k)] = string(v)
	}
	return out, nil
}
func (s *Service) createGroup(tx Transaction, in *api.CreateGroupInput) (*api.CreateGroupOutput, error) {
	scope := scopeFor(tx.Context())
	tags, err := tagsInput(in.Tags)
	if err != nil {
		return nil, err
	}
	g := Group{Scope: scope, ARN: groupARN(scope, value(in.Name)), Name: value(in.Name), Description: value(in.Description), Tags: tags, Created: s.clock.Now()}
	if err := s.authorize(tx.Context(), "CreateGroup", nil, tags, slices.Sorted(maps.Keys(tags))); err != nil {
		return nil, err
	}
	if len(tags) > 0 {
		target := Group{Scope: scope, ARN: g.ARN}
		if err := s.authorize(tx.Context(), "Tag", &target, tags, slices.Sorted(maps.Keys(tags))); err != nil {
			return nil, err
		}
	}
	if in.DisplayName != nil || in.Owner != nil || in.Criticality != nil {
		return nil, failure("BadRequestException", "Unsupported parameter for this operation")
	}
	if strings.HasPrefix(strings.ToLower(g.Name), "aws") {
		return nil, failure("BadRequestException", "Group names beginning with AWS are reserved.")
	}
	if _, ok, err := tx.Group(scope, g.ARN); err != nil {
		return nil, err
	} else if ok {
		return nil, failure("BadRequestException", "A group with the specified name already exists.")
	}
	if in.ResourceQuery == nil && len(in.Configuration) == 0 {
		return nil, failure("BadRequestException", "Specify a ResourceQuery or Configuration.")
	}
	if len(in.Configuration) > 0 {
		return nil, configurationError(in.Configuration, in.ResourceQuery)
	}
	if err := s.validateQuery(tx.Context(), in.ResourceQuery); err != nil {
		return nil, err
	}
	g.Query = in.ResourceQuery
	if len(g.Tags) > 50 {
		return nil, failure("BadRequestException", "A group may have at most 50 tags.")
	}
	g.CloudFormationClaim = cloudFormationGroupClaim(tx.Context())
	if err := tx.PutGroup(g); err != nil {
		return nil, err
	}
	out := &api.CreateGroupOutput{Group: groupOutput(g), ResourceQuery: g.Query, Tags: tagsOutput(g.Tags)}
	return out, nil
}
func (s *Service) getGroup(tx Transaction, in *api.GetGroupInput) (*api.GetGroupOutput, error) {
	id, err := identifier(value(in.Group), value(in.GroupName))
	if err != nil {
		return nil, err
	}
	g, err := s.loadGroup(tx, id, "GetGroup")
	if err != nil {
		return nil, err
	}
	return &api.GetGroupOutput{Group: groupOutput(g)}, nil
}
func (s *Service) deleteGroup(tx Transaction, in *api.DeleteGroupInput) (*api.DeleteGroupOutput, error) {
	id, err := identifier(value(in.Group), value(in.GroupName))
	if err != nil {
		return nil, err
	}
	g, err := s.loadGroup(tx, id, "DeleteGroup")
	if err != nil {
		return nil, err
	}
	if g.ApplicationARN != "" {
		return nil, failure("ForbiddenException", "Access denied. This group is managed by AppRegistry.")
	}
	if err := tx.DeleteGroup(g.Scope, g.ARN); err != nil {
		return nil, err
	}
	return &api.DeleteGroupOutput{Group: groupOutput(g)}, nil
}
func (s *Service) updateGroup(tx Transaction, in *api.UpdateGroupInput) (*api.UpdateGroupOutput, error) {
	id, err := identifier(value(in.Group), value(in.GroupName))
	if err != nil {
		return nil, err
	}
	g, err := s.loadGroup(tx, id, "UpdateGroup")
	if err != nil {
		return nil, err
	}
	if g.ApplicationARN != "" && g.ManagedType != applicationGroupType {
		return nil, failure("ForbiddenException", "Access denied. This group is managed by AppRegistry.")
	}
	if in.Description != nil {
		g.Description = value(in.Description)
	}
	if g.ManagedType == applicationGroupType {
		if in.DisplayName != nil {
			g.DisplayName = value(in.DisplayName)
		}
		if in.Owner != nil {
			g.Owner = value(in.Owner)
		}
		if in.Criticality != nil {
			g.Criticality = new(int32(*in.Criticality))
		}
	} else if in.DisplayName != nil || in.Owner != nil || in.Criticality != nil {
		return nil, failure("BadRequestException", "Unsupported parameter for this operation")
	}
	if err := tx.PutGroup(g); err != nil {
		return nil, err
	}
	return &api.UpdateGroupOutput{Group: groupOutput(g)}, nil
}
func (s *Service) listGroups(tx Transaction, in *api.ListGroupsInput) (*api.ListGroupsOutput, error) {
	if err := s.authorize(tx.Context(), "ListGroups", nil, nil, nil); err != nil {
		return nil, err
	}
	if err := validateGroupFilters(in.Filters); err != nil {
		return nil, err
	}
	rows, err := tx.Groups(scopeFor(tx.Context()))
	if err != nil {
		return nil, err
	}
	selected := make([]Group, 0, len(rows))
	for _, g := range rows {
		if matchesGroupFilters(g, in.Filters) {
			selected = append(selected, g)
		}
	}
	page, next, err := paginate(tx.Context(), "ListGroups", in.Filters, in.NextToken, in.MaxResults, selected, func(g Group) string { return g.ARN })
	if err != nil {
		return nil, err
	}
	out := &api.ListGroupsOutput{Groups: api.GroupList{}, GroupIdentifiers: api.GroupIdentifierList{}, NextToken: next}
	for _, g := range page {
		v := groupOutput(g)
		out.Groups = append(out.Groups, *v)
		out.GroupIdentifiers = append(out.GroupIdentifiers, api.GroupIdentifier{GroupArn: new(api.GroupArn(g.ARN)), GroupName: new(api.GroupName(g.Name)), Description: v.Description, DisplayName: v.DisplayName, Owner: v.Owner, Criticality: v.Criticality})
	}
	return out, nil
}
func validateGroupFilters(filters api.GroupFilterList) error {
	seen := map[string]bool{}
	for _, f := range filters {
		name := value(f.Name)
		if seen[name] {
			return failure("BadRequestException", "Duplicate group filter: "+name)
		}
		seen[name] = true
		switch name {
		case "resource-type", "configuration-type", "criticality", "display-name", "owner":
		default:
			return failure("BadRequestException", "Unsupported group filter: "+name)
		}
		if len(f.Values) == 0 {
			return failure("BadRequestException", "Group filters require values.")
		}
	}
	return nil
}
func matchesGroupFilters(g Group, filters api.GroupFilterList) bool {
	for _, f := range filters {
		matched := false
		for _, v := range f.Values {
			switch value(f.Name) {
			case "owner":
				matched = matched || g.ManagedType == applicationGroupType && g.Owner == string(v)
			case "display-name":
				matched = matched || g.ManagedType == applicationGroupType && g.DisplayName == string(v)
			case "criticality":
				matched = matched || g.ManagedType == applicationGroupType && g.Criticality != nil && strconv.Itoa(int(*g.Criticality)) == string(v)
			case "configuration-type":
				matched = matched || g.ManagedType == string(v)
			case "resource-type":
				if g.Query != nil {
					q, err := parseQuery(g.Query)
					matched = matched || (err == nil && slices.Contains(q.ResourceTypeFilters, string(v)))
				}
			}
		}
		if !matched {
			return false
		}
	}
	return true
}
func (s *Service) getTags(tx Transaction, in *api.GetTagsInput) (*api.GetTagsOutput, error) {
	g, err := s.loadGroup(tx, value(in.Arn), "GetTags")
	if err != nil {
		return nil, err
	}
	return &api.GetTagsOutput{Arn: new(api.GroupArnV2(g.ARN)), Tags: tagsOutput(g.Tags)}, nil
}
func (s *Service) tag(tx Transaction, in *api.TagInput) (*api.TagOutput, error) {
	tags, err := tagsInput(in.Tags)
	if err != nil {
		return nil, err
	}
	g, ok, err := tx.Group(scopeFor(tx.Context()), value(in.Arn))
	if err != nil {
		return nil, err
	}
	if !ok {
		g = Group{Scope: scopeFor(tx.Context()), ARN: value(in.Arn)}
	}
	if err := s.authorize(tx.Context(), "Tag", &g, tags, slices.Sorted(maps.Keys(tags))); err != nil {
		return nil, err
	}
	if !ok {
		return nil, failure("NotFoundException", "The specified group does not exist.")
	}
	if err := observeCloudFormationGroup(tx.Context(), g); err != nil {
		return nil, err
	}
	if g.Tags == nil {
		g.Tags = map[string]string{}
	}
	maps.Copy(g.Tags, tags)
	if len(g.Tags) > 50 {
		return nil, failure("BadRequestException", "A group may have at most 50 tags.")
	}
	if err := tx.PutGroup(g); err != nil {
		return nil, err
	}
	return &api.TagOutput{Arn: new(api.GroupArnV2(g.ARN)), Tags: tagsOutput(tags)}, nil
}
func (s *Service) untag(tx Transaction, in *api.UntagInput) (*api.UntagOutput, error) {
	g, ok, err := tx.Group(scopeFor(tx.Context()), value(in.Arn))
	if err != nil {
		return nil, err
	}
	if !ok {
		g = Group{Scope: scopeFor(tx.Context()), ARN: value(in.Arn)}
	}
	keys := make([]string, len(in.Keys))
	for i, k := range in.Keys {
		keys[i] = string(k)
	}
	if err := s.authorize(tx.Context(), "Untag", &g, nil, keys); err != nil {
		return nil, err
	}
	if !ok {
		return nil, failure("NotFoundException", "The specified group does not exist.")
	}
	if err := observeCloudFormationGroup(tx.Context(), g); err != nil {
		return nil, err
	}
	for _, k := range keys {
		if strings.HasPrefix(strings.ToLower(k), "aws:") {
			return nil, failure("BadRequestException", "Tag keys beginning with aws: are reserved.")
		}
		delete(g.Tags, k)
	}
	if err := tx.PutGroup(g); err != nil {
		return nil, err
	}
	return &api.UntagOutput{Arn: new(api.GroupArnV2(g.ARN)), Keys: in.Keys}, nil
}
