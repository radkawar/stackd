package scheduler

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"slices"
	"strings"

	api "stackd/internal/awsapi/scheduler"
)

func (s *Service) registerGroups() {
	register(s, "CreateScheduleGroup", s.createGroup)
	register(s, "GetScheduleGroup", s.getGroup)
	register(s, "ListScheduleGroups", s.listGroups)
	register(s, "DeleteScheduleGroup", s.deleteGroup)
}

func (s *Service) group(tx Transaction, k GroupKey) (GroupRecord, error) {
	v, err := tx.Group(k)
	if errors.Is(err, ErrNotFound) && k.Name == "default" {
		now := s.clock.Now()
		v = GroupRecord{
			Key:      k,
			Created:  now,
			Modified: now,
			Tags:     map[string]string{},
		}
		err = tx.PutGroup(v)
	}
	return v, err
}

func tagInput(tags api.TagList) (map[string]string, map[string][]string, error) {
	out := map[string]string{}
	conditions := map[string][]string{}
	for _, t := range tags {
		k, v := value(t.Key), value(t.Value)
		if k == "" || len(k) > 128 || len(v) > 256 || strings.HasPrefix(strings.ToLower(k), "aws:") {
			return nil, nil, failure("ValidationException", "Invalid tag.")
		}
		if _, ok := out[k]; ok {
			return nil, nil, failure("ValidationException", "Duplicate tag key.")
		}
		out[k] = v
		conditions["aws:RequestTag/"+k] = []string{v}
		conditions["aws:TagKeys"] = append(conditions["aws:TagKeys"], k)
	}
	if len(out) > 50 {
		return nil, nil, failure("ServiceQuotaExceededException", "A schedule group supports at most 50 tags.", 402)
	}
	return out, conditions, nil
}

func (s *Service) createGroup(tx Transaction, in *api.CreateScheduleGroupInput) (*api.CreateScheduleGroupOutput, error) {
	k := GroupKey{
		scopeFor(tx.Context()),
		value(in.Name),
	}
	if !validName(k.Name) {
		return nil, failure("ValidationException", "Invalid group name.")
	}
	tags, c, err := tagInput(in.Tags)
	if err != nil {
		return nil, err
	}
	if err = s.authorize(tx, "CreateScheduleGroup", k.ARN(), nil, c); err != nil {
		return nil, err
	}
	old, err := s.group(tx, k)
	if err == nil {
		if value(in.ClientToken) != "" && value(in.ClientToken) == old.ClientToken {
			return &api.CreateScheduleGroupOutput{ScheduleGroupArn: new(api.ScheduleGroupArn(k.ARN()))}, nil
		}
		return nil, failure("ConflictException", "A schedule group with this name already exists.", 409)
	}
	if !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	now := s.clock.Now()
	if err = tx.PutGroup(GroupRecord{
		Key:         k,
		Created:     now,
		Modified:    now,
		Tags:        tags,
		ClientToken: value(in.ClientToken),
	}); err != nil {
		return nil, err
	}
	return &api.CreateScheduleGroupOutput{ScheduleGroupArn: new(api.ScheduleGroupArn(k.ARN()))}, nil
}

func (s *Service) getGroup(tx Transaction, in *api.GetScheduleGroupInput) (*api.GetScheduleGroupOutput, error) {
	k := GroupKey{
		scopeFor(tx.Context()),
		value(in.Name),
	}
	v, err := s.group(tx, k)
	if err != nil {
		return nil, err
	}
	if err = s.authorize(tx, "GetScheduleGroup", k.ARN(), v.Tags, nil); err != nil {
		return nil, err
	}
	return &api.GetScheduleGroupOutput{
		Arn:                  new(api.ScheduleGroupArn(k.ARN())),
		Name:                 in.Name,
		State:                new(api.ScheduleGroupState("ACTIVE")),
		CreationDate:         &v.Created,
		LastModificationDate: &v.Modified,
	}, nil
}

func (s *Service) deleteGroup(tx Transaction, in *api.DeleteScheduleGroupInput) (*api.DeleteScheduleGroupOutput, error) {
	k := GroupKey{
		scopeFor(tx.Context()),
		value(in.Name),
	}
	v, err := s.group(tx, k)
	if err != nil {
		return nil, err
	}
	if err = s.authorize(tx, "DeleteScheduleGroup", k.ARN(), v.Tags, nil); err != nil {
		return nil, err
	}
	if k.Name == "default" {
		return nil, failure("ValidationException", "The default schedule group cannot be deleted.")
	}
	if err = tx.DeleteGroupDeliveries(k); err != nil {
		return nil, err
	}
	rows, err := tx.Schedules(k.Scope)
	if err != nil {
		return nil, err
	}
	for _, row := range rows {
		if row.Key.Group == k {
			if err = tx.DeleteSchedule(row.Key); err != nil {
				return nil, err
			}
		}
	}
	if err = tx.DeleteGroup(k); err != nil {
		return nil, err
	}
	return &api.DeleteScheduleGroupOutput{}, nil
}

func pagination(token, binding string, limit *api.MaxResults) (string, int, error) {
	n := 100
	if limit != nil {
		n = int(*limit)
	}
	if n < 1 || n > 100 {
		return "", 0, failure("ValidationException", "MaxResults must be between 1 and 100.")
	}
	if token == "" {
		return "", n, nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return "", 0, failure("ValidationException", "Invalid NextToken.")
	}
	fingerprint, last, ok := strings.Cut(string(raw), "\n")
	hash := sha256.Sum256([]byte(binding))
	if !ok || fingerprint != hex.EncodeToString(hash[:]) {
		return "", 0, failure("ValidationException", "Invalid NextToken.")
	}
	return last, n, nil
}

func nextToken(binding, last string) *api.NextToken {
	hash := sha256.Sum256([]byte(binding))
	return new(api.NextToken(base64.RawURLEncoding.EncodeToString([]byte(hex.EncodeToString(hash[:]) + "\n" + last))))
}

func scopeBinding(k Scope) string {
	return k.Partition + ":" + k.Account + ":" + k.Region
}

func (s *Service) listGroups(tx Transaction, in *api.ListScheduleGroupsInput) (*api.ListScheduleGroupsOutput, error) {
	scope := scopeFor(tx.Context())
	if err := s.authorize(tx, "ListScheduleGroups", "*", nil, nil); err != nil {
		return nil, err
	}
	binding := "groups:" + scopeBinding(scope) + ":" + value(in.NamePrefix)
	last, n, err := pagination(value(in.NextToken), binding, in.MaxResults)
	if err != nil {
		return nil, err
	}
	if _, err = s.group(tx, GroupKey{
		scope,
		"default",
	}); err != nil {
		return nil, err
	}
	rows, err := tx.Groups(scope)
	if err != nil {
		return nil, err
	}
	out := &api.ListScheduleGroupsOutput{ScheduleGroups: api.ScheduleGroupList{}}
	for _, v := range rows {
		if v.Key.Name <= last || !strings.HasPrefix(v.Key.Name, value(in.NamePrefix)) {
			continue
		}
		if len(out.ScheduleGroups) == n {
			out.NextToken = nextToken(binding, value(out.ScheduleGroups[n-1].Name))
			break
		}
		out.ScheduleGroups = append(out.ScheduleGroups, api.ScheduleGroupSummary{
			Arn:                  new(api.ScheduleGroupArn(v.Key.ARN())),
			Name:                 new(api.ScheduleGroupName(v.Key.Name)),
			State:                new(api.ScheduleGroupState("ACTIVE")),
			CreationDate:         &v.Created,
			LastModificationDate: &v.Modified,
		})
	}
	return out, nil
}

func (s *Service) registerTags() {
	register(s, "TagResource", s.tag)
	register(s, "UntagResource", s.untag)
	register(s, "ListTagsForResource", s.listTags)
}

func (s *Service) taggedGroup(tx Transaction, resource, action string, c map[string][]string) (GroupRecord, error) {
	scope := scopeFor(tx.Context())
	prefix := "arn:" + scope.Partition + ":scheduler:" + scope.Region + ":" + scope.Account + ":schedule-group/"
	if !strings.HasPrefix(resource, prefix) || !validName(strings.TrimPrefix(resource, prefix)) {
		return GroupRecord{}, failure("ValidationException", "Only schedule groups in this scope can be tagged.")
	}
	v, err := s.group(tx, GroupKey{
		scope,
		strings.TrimPrefix(resource, prefix),
	})
	if err != nil {
		return v, err
	}
	return v, s.authorize(tx, action, resource, v.Tags, c)
}

func (s *Service) tag(tx Transaction, in *api.TagResourceInput) (*api.TagResourceOutput, error) {
	tags, c, err := tagInput(in.Tags)
	if err != nil {
		return nil, err
	}
	v, err := s.taggedGroup(tx, value(in.ResourceArn), "TagResource", c)
	if err != nil {
		return nil, err
	}
	if v.Tags == nil {
		v.Tags = map[string]string{}
	}
	for k, t := range tags {
		v.Tags[k] = t
	}
	if len(v.Tags) > 50 {
		return nil, failure("ServiceQuotaExceededException", "A schedule group supports at most 50 tags.", 402)
	}
	if err = tx.PutGroup(v); err != nil {
		return nil, err
	}
	return &api.TagResourceOutput{}, nil
}

func (s *Service) untag(tx Transaction, in *api.UntagResourceInput) (*api.UntagResourceOutput, error) {
	var keys []string
	if len(in.TagKeys) != 0 {
		keys = make([]string, len(in.TagKeys))
	}
	for i, k := range in.TagKeys {
		keys[i] = string(k)
	}
	v, err := s.taggedGroup(tx, value(in.ResourceArn), "UntagResource", map[string][]string{"aws:TagKeys": keys})
	if err != nil {
		return nil, err
	}
	for _, k := range keys {
		delete(v.Tags, k)
	}
	if err = tx.PutGroup(v); err != nil {
		return nil, err
	}
	return &api.UntagResourceOutput{}, nil
}

func (s *Service) listTags(tx Transaction, in *api.ListTagsForResourceInput) (*api.ListTagsForResourceOutput, error) {
	v, err := s.taggedGroup(tx, value(in.ResourceArn), "ListTagsForResource", nil)
	if err != nil {
		return nil, err
	}
	keys := make([]string, 0, len(v.Tags))
	for k := range v.Tags {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	out := &api.ListTagsForResourceOutput{Tags: api.TagList{}}
	for _, k := range keys {
		out.Tags = append(out.Tags, api.Tag{
			Key:   new(api.TagKey(k)),
			Value: new(api.TagValue(v.Tags[k])),
		})
	}
	return out, nil
}
