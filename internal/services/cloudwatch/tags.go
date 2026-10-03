package cloudwatch

import (
	"maps"
	"slices"
	"strings"
	"time"

	api "stackd/internal/awsapi/cloudwatch"
	"stackd/internal/awswire"
)

func cloudwatchTagConditions(current, requested map[string]string, keys []string) map[string][]string {
	conditions := make(map[string][]string, len(current)+len(requested)+1)
	for key, value := range current {
		conditions["aws:ResourceTag/"+key] = []string{value}
	}
	allKeys := make([]string, 0, len(keys)+len(requested))
	allKeys = append(allKeys, keys...)
	for key, value := range requested {
		conditions["aws:RequestTag/"+key] = []string{value}
		allKeys = append(allKeys, key)
	}
	if len(allKeys) != 0 {
		slices.Sort(allKeys)
		conditions["aws:TagKeys"] = slices.Compact(allKeys)
	}
	return conditions
}

func admitTagKey(key string) *awswire.Error {
	if len(key) >= 4 && strings.EqualFold(key[:4], "aws:") {
		return failure("AccessDenied", "The provided tag keys must not start with any case of \"aws:\"")
	}
	return nil
}

func admitTags(input api.TagList) (map[string]string, *awswire.Error) {
	tags := make(map[string]string, len(input))
	for _, tag := range input {
		key := value(tag.Key)
		if w := admitTagKey(key); w != nil {
			return nil, w
		}
		tags[key] = value(tag.Value)
	}
	return tags, nil
}

// A tag command authorizes the concrete resource before reading or replacing
// its detached tag map. Each owner preserves its own modification semantics.
type taggableResource interface {
	resourceTags() map[string]string
	putResourceTags(Transaction, map[string]string, time.Time) error
}

func (a *AlarmRecord) resourceTags() map[string]string { return a.Tags }
func (a *AlarmRecord) putResourceTags(tx Transaction, tags map[string]string, _ time.Time) error {
	a.Tags = tags
	return tx.PutAlarm(*a)
}

func (d *DashboardRecord) resourceTags() map[string]string { return d.Tags }
func (d *DashboardRecord) putResourceTags(tx Transaction, tags map[string]string, at time.Time) error {
	d.Tags = tags
	d.TaggingInitialized = true
	return storeDashboard(tx, *d, at)
}

func (s *Service) tagTarget(tx Transaction, arn, action string, requested map[string]string, keys []string) (taggableResource, *awswire.Error) {
	if strings.Contains(arn, ":dashboard/") {
		return s.dashboardTagTarget(tx, arn, action, requested, keys)
	}
	alarm, w := s.alarmTagTarget(tx, arn, action, requested, keys)
	if w != nil {
		return nil, w
	}
	return &alarm, nil
}

func (s *Service) tagResource(tx Transaction, in *api.TagResourceInput) (*api.TagResourceOutput, *awswire.Error) {
	if len(in.Tags) == 0 {
		return nil, invalid("tags cannot be empty.")
	}
	requested, w := admitTags(in.Tags)
	if w != nil {
		return nil, w
	}
	target, w := s.tagTarget(tx, value(in.ResourceARN), "TagResource", requested, nil)
	if w != nil {
		return nil, w
	}
	tags := target.resourceTags()
	if tags == nil {
		tags = make(map[string]string)
	}
	maps.Copy(tags, requested)
	if len(tags) > 50 {
		return nil, invalid("tags are invalid.")
	}
	if err := target.putResourceTags(tx, tags, s.clock.Now()); err != nil {
		return nil, wireError(err)
	}
	return &api.TagResourceOutput{}, nil
}

func (s *Service) untagResource(tx Transaction, in *api.UntagResourceInput) (*api.UntagResourceOutput, *awswire.Error) {
	if len(in.TagKeys) == 0 {
		return nil, invalid("tagKeys cannot be empty.")
	}
	keys := make([]string, len(in.TagKeys))
	for i, key := range in.TagKeys {
		keys[i] = string(key)
		if w := admitTagKey(string(key)); w != nil {
			return nil, w
		}
	}
	target, w := s.tagTarget(tx, value(in.ResourceARN), "UntagResource", nil, keys)
	if w != nil {
		return nil, w
	}
	tags := target.resourceTags()
	for _, key := range keys {
		delete(tags, key)
	}
	if err := target.putResourceTags(tx, tags, s.clock.Now()); err != nil {
		return nil, wireError(err)
	}
	return &api.UntagResourceOutput{}, nil
}

func (s *Service) listResourceTags(tx Transaction, in *api.ListTagsForResourceInput) (*api.ListTagsForResourceOutput, *awswire.Error) {
	target, w := s.tagTarget(tx, value(in.ResourceARN), "ListTagsForResource", nil, nil)
	if w != nil {
		return nil, w
	}
	tags := target.resourceTags()
	out := &api.ListTagsForResourceOutput{Tags: api.TagList{}}
	for _, key := range slices.Sorted(maps.Keys(tags)) {
		out.Tags = append(out.Tags, api.Tag{Key: new(api.TagKey(key)), Value: new(api.TagValue(tags[key]))})
	}
	return out, nil
}
