package logs

import (
	"strings"
	"unicode/utf8"

	api "stackd/internal/awsapi/logs"
	"stackd/internal/awswire"
)

func tagValues(in api.Tags) (map[string]string, *awswire.Error) {
	out := make(map[string]string, len(in))
	if len(in) > 50 {
		return nil, invalid("A resource can have at most 50 tags.")
	}
	for k, v := range in {
		key := string(k)
		if utf8.RuneCountInString(key) < 1 || utf8.RuneCountInString(key) > 128 || utf8.RuneCountInString(string(v)) > 256 || strings.HasPrefix(strings.ToLower(key), "aws:") {
			return nil, invalid("The tag key or value is invalid.")
		}
		out[key] = string(v)
	}
	return out, nil
}
func apiTags(tags map[string]string) api.Tags {
	out := api.Tags{}
	for k, v := range tags {
		out[api.TagKey(k)] = api.TagValue(v)
	}
	return out
}
func (s *Service) changeTags(tx Transaction, ref, action string, input api.Tags, remove []string) (*api.Unit, *awswire.Error) {
	if (action == "TagResource" || action == "UntagResource") && (!strings.HasPrefix(ref, "arn:") || strings.HasSuffix(ref, ":*")) {
		return nil, invalid("resourceArn must be a log group ARN without a trailing wildcard.")
	}
	tags, w := tagValues(input)
	if w != nil {
		return nil, w
	}
	if strings.Contains(ref, ":destination:") && (action == "TagResource" || action == "UntagResource") {
		d, w := s.destinationForTagging(tx, ref, action, tags, remove)
		if w != nil {
			return nil, w
		}
		if d.Tags == nil {
			d.Tags = map[string]string{}
		}
		for k, v := range tags {
			d.Tags[k] = v
		}
		for _, k := range remove {
			delete(d.Tags, k)
		}
		if len(d.Tags) > 50 {
			return nil, invalid("A resource can have at most 50 tags.")
		}
		return &api.Unit{}, wireError(tx.PutDestination(d))
	}
	k, w := groupKey(tx.Context(), ref)
	if w != nil {
		return nil, w
	}
	g, err := tx.Group(k)
	if err != nil {
		g.Key = k
	}
	if w := s.authorize(tx, action, g, "", tags, remove); w != nil {
		return nil, w
	}
	if err != nil {
		return nil, wireError(err)
	}
	if g.Tags == nil {
		g.Tags = map[string]string{}
	}
	for k, v := range tags {
		g.Tags[k] = v
	}
	for _, k := range remove {
		delete(g.Tags, k)
	}
	if len(g.Tags) > 50 {
		return nil, invalid("A log group can have at most 50 tags.")
	}
	if err := tx.PutGroup(g); err != nil {
		return nil, wireError(err)
	}
	return &api.Unit{}, nil
}
func (s *Service) tagResource(tx Transaction, in *api.TagResourceRequest) (*api.Unit, *awswire.Error) {
	return s.changeTags(tx, value(in.ResourceArn), "TagResource", in.Tags, nil)
}
func (s *Service) tagLogGroup(tx Transaction, in *api.TagLogGroupRequest) (*api.Unit, *awswire.Error) {
	return s.changeTags(tx, value(in.LogGroupName), "TagLogGroup", in.Tags, nil)
}
func (s *Service) untagResource(tx Transaction, in *api.UntagResourceRequest) (*api.Unit, *awswire.Error) {
	keys := make([]string, len(in.TagKeys))
	for i, k := range in.TagKeys {
		keys[i] = string(k)
	}
	return s.changeTags(tx, value(in.ResourceArn), "UntagResource", nil, keys)
}
func (s *Service) untagLogGroup(tx Transaction, in *api.UntagLogGroupRequest) (*api.Unit, *awswire.Error) {
	keys := make([]string, len(in.Tags))
	for i, k := range in.Tags {
		keys[i] = string(k)
	}
	return s.changeTags(tx, value(in.LogGroupName), "UntagLogGroup", nil, keys)
}
func (s *Service) listTagsForResource(tx Transaction, in *api.ListTagsForResourceRequest) (*api.ListTagsForResourceResponse, *awswire.Error) {
	ref := value(in.ResourceArn)
	if !strings.HasPrefix(ref, "arn:") || strings.HasSuffix(ref, ":*") {
		return nil, invalid("resourceArn must be a log group ARN without a trailing wildcard.")
	}
	if strings.Contains(ref, ":destination:") {
		d, w := s.destinationForTagging(tx, ref, "ListTagsForResource", nil, nil)
		if w != nil {
			return nil, w
		}
		return &api.ListTagsForResourceResponse{Tags: apiTags(d.Tags)}, nil
	}
	g, w := s.loadGroup(tx, ref, "ListTagsForResource", "")
	if w != nil {
		return nil, w
	}
	return &api.ListTagsForResourceResponse{Tags: apiTags(g.Tags)}, nil
}
func (s *Service) listTagsLogGroup(tx Transaction, in *api.ListTagsLogGroupRequest) (*api.ListTagsLogGroupResponse, *awswire.Error) {
	g, w := s.loadGroup(tx, value(in.LogGroupName), "ListTagsLogGroup", "")
	if w != nil {
		return nil, w
	}
	return &api.ListTagsLogGroupResponse{Tags: apiTags(g.Tags)}, nil
}

func (s *Service) destinationForTagging(r Reader, arn, action string, tags map[string]string, keys []string) (DestinationRecord, *awswire.Error) {
	k, w := destinationARN(arn)
	if w != nil {
		return DestinationRecord{}, w
	}
	if k.Scope != scopeFor(r.Context()) {
		return DestinationRecord{}, invalid("The specified destination does not exist.")
	}
	d, err := r.Destination(k)
	d.Key = k
	if w := s.authorizeDestination(r, action, d, tags, keys); w != nil {
		return d, w
	}
	return d, wireError(err)
}
func (s *Service) putRetentionPolicy(tx Transaction, in *api.PutRetentionPolicyRequest) (*api.Unit, *awswire.Error) {
	if in.RetentionInDays == nil {
		return nil, invalid("retentionInDays is required.")
	}
	days := int32(*in.RetentionInDays)
	switch days {
	case 1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1096, 1827, 2192, 2557, 2922, 3288, 3653:
	default:
		return nil, invalid("retentionInDays is not a supported retention period.")
	}
	return s.retention(tx, value(in.LogGroupName), "PutRetentionPolicy", days)
}
func (s *Service) deleteRetentionPolicy(tx Transaction, in *api.DeleteRetentionPolicyRequest) (*api.Unit, *awswire.Error) {
	return s.retention(tx, value(in.LogGroupName), "DeleteRetentionPolicy", 0)
}
func (s *Service) retention(tx Transaction, ref, action string, days int32) (*api.Unit, *awswire.Error) {
	g, w := s.loadGroup(tx, ref, action, "")
	if w != nil {
		return nil, w
	}
	g.RetentionDays = days
	if err := tx.PutGroup(g); err != nil {
		return nil, wireError(err)
	}
	return &api.Unit{}, nil
}
