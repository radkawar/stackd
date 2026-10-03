package autoscaling

import (
	"context"
	"errors"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"

	api "stackd/internal/awsapi/autoscaling"
)

func registerTags(s *Service) {
	register(s, "CreateOrUpdateTags", s.createOrUpdateTags)
	register(s, "DeleteTags", s.deleteTags)
	register(s, "DescribeTags", s.describeTags)
}

func validateTag(tag api.Tag, groupName string) error {
	key := value(tag.Key)
	if key == "" || utf8.RuneCountInString(key) > 128 || utf8.RuneCountInString(value(tag.Value)) > 256 || strings.HasPrefix(strings.ToLower(key), "aws:") {
		return invalid("The tag key or value is not valid; the aws: prefix is reserved.")
	}
	if resource := value(tag.ResourceId); resource != "" && resource != groupName {
		return invalid("The tag resource ID does not match the Auto Scaling group.")
	}
	if resourceType := value(tag.ResourceType); resourceType != "" && resourceType != "auto-scaling-group" {
		return invalid("The tag resource type must be auto-scaling-group.")
	}
	return nil
}

func applyGroupTags(group *GroupRecord, tags api.Tags) error {
	byKey := make(map[string]api.TagDescription, len(group.Data.Tags)+len(tags))
	for _, tag := range group.Data.Tags {
		byKey[value(tag.Key)] = tag
	}
	for _, tag := range tags {
		if err := validateTag(tag, group.Key.Name); err != nil {
			return err
		}
		propagate := false
		if tag.PropagateAtLaunch != nil {
			propagate = bool(*tag.PropagateAtLaunch)
		}
		byKey[value(tag.Key)] = api.TagDescription{Key: tag.Key, Value: new(api.TagValue(value(tag.Value))), ResourceId: new(api.XmlString(group.Key.Name)), ResourceType: new(api.XmlString("auto-scaling-group")), PropagateAtLaunch: new(api.PropagateAtLaunch(propagate))}
	}
	if len(byKey) > 50 {
		return failure("LimitExceeded", "The Auto Scaling group has reached its tag limit.")
	}
	group.Data.Tags = make(api.TagDescriptionList, 0, len(byKey))
	for _, tag := range byKey {
		group.Data.Tags = append(group.Data.Tags, tag)
	}
	slices.SortFunc(group.Data.Tags, func(a, b api.TagDescription) int { return strings.Compare(value(a.Key), value(b.Key)) })
	return nil
}

func tagsByGroup(tags api.Tags) (map[string]api.Tags, error) {
	if len(tags) == 0 {
		return nil, invalid("At least one tag must be specified.")
	}
	groups := map[string]api.Tags{}
	for _, tag := range tags {
		name := value(tag.ResourceId)
		if name == "" {
			return nil, invalid("A resource ID must be specified for each tag.")
		}
		if err := validateTag(tag, name); err != nil {
			return nil, err
		}
		groups[name] = append(groups[name], tag)
	}
	return groups, nil
}

func (s *Service) createOrUpdateTags(ctx context.Context, tx Transaction, in *api.CreateOrUpdateTagsInput) (*api.CreateOrUpdateTagsOutput, error) {
	groups, err := tagsByGroup(in.Tags)
	if err != nil {
		return nil, err
	}
	for name, tags := range groups {
		group, err := tx.Group(GroupKey{Scope: scopeFor(ctx), Name: name})
		if errors.Is(err, ErrNotFound) {
			return nil, invalid("AutoScalingGroup name not found - AutoScalingGroup " + name + " not found")
		}
		if err != nil {
			return nil, err
		}
		conditions := groupConditions(group)
		requestTagConditions(conditions, tags)
		if err := s.authorize(ctx, "CreateOrUpdateTags", group.Key.ARN(group.ID), conditions); err != nil {
			return nil, err
		}
		if err := applyGroupTags(&group, tags); err != nil {
			return nil, err
		}
		if err := tx.PutGroup(group); err != nil {
			return nil, err
		}
	}
	return &api.CreateOrUpdateTagsOutput{}, nil
}

func (s *Service) deleteTags(ctx context.Context, tx Transaction, in *api.DeleteTagsInput) (*api.DeleteTagsOutput, error) {
	groups, err := tagsByGroup(in.Tags)
	if err != nil {
		return nil, err
	}
	for name, tags := range groups {
		group, err := tx.Group(GroupKey{Scope: scopeFor(ctx), Name: name})
		if errors.Is(err, ErrNotFound) {
			return nil, invalid("AutoScalingGroup name not found - AutoScalingGroup " + name + " not found")
		}
		if err != nil {
			return nil, err
		}
		conditions := groupConditions(group)
		requestTagConditions(conditions, tags)
		if err := s.authorize(ctx, "DeleteTags", group.Key.ARN(group.ID), conditions); err != nil {
			return nil, err
		}
		group.Data.Tags = slices.DeleteFunc(group.Data.Tags, func(existing api.TagDescription) bool {
			return slices.ContainsFunc(tags, func(tag api.Tag) bool {
				return value(tag.Key) == value(existing.Key) && (tag.Value == nil || value(tag.Value) == value(existing.Value))
			})
		})
		if err := tx.PutGroup(group); err != nil {
			return nil, err
		}
	}
	return &api.DeleteTagsOutput{}, nil
}

func (s *Service) describeTags(ctx context.Context, tx Transaction, in *api.DescribeTagsInput) (*api.DescribeTagsOutput, error) {
	if err := s.authorize(ctx, "DescribeTags", "*", nil); err != nil {
		return nil, err
	}
	filters := canonicalFilters(in.Filters)
	for _, filter := range filters {
		if !slices.Contains([]string{"auto-scaling-group", "key", "value", "propagate-at-launch"}, value(filter.Name)) {
			return nil, invalid("The tag filter name is not valid: " + value(filter.Name))
		}
		if len(filter.Values) == 0 {
			return nil, invalid("Filter values must not be empty.")
		}
	}
	groups, err := tx.Groups(GroupQuery{Scope: scopeFor(ctx)})
	if err != nil {
		return nil, err
	}
	tags := []api.TagDescription{}
	for _, group := range groups {
		for _, tag := range group.Data.Tags {
			matched := true
			for _, filter := range filters {
				var candidate string
				switch value(filter.Name) {
				case "auto-scaling-group":
					candidate = group.Key.Name
				case "key":
					candidate = value(tag.Key)
				case "value":
					candidate = value(tag.Value)
				case "propagate-at-launch":
					candidate = strconv.FormatBool(tag.PropagateAtLaunch != nil && bool(*tag.PropagateAtLaunch))
				}
				if !slices.Contains(filter.Values, api.XmlString(candidate)) {
					matched = false
					break
				}
			}
			if matched {
				tags = append(tags, tag)
			}
		}
	}
	tags, next, err := pageRows(scopeFor(ctx), "DescribeTags", filters, in.MaxRecords, in.NextToken, tags, func(tag api.TagDescription) string { return value(tag.ResourceId) + "\x00" + value(tag.Key) })
	if err != nil {
		return nil, err
	}
	return &api.DescribeTagsOutput{Tags: tags, NextToken: next}, nil
}
