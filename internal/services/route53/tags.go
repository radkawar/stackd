package route53

import (
	"slices"
	api "stackd/internal/awsapi/route53"
	"strings"
	"unicode/utf8"
)

func (s *Service) taggedZone(tx Transaction, kind, id, op string) (Zone, error) {
	if kind == "healthcheck" {
		return Zone{}, failure("NotImplemented", "Health check tags require an implemented health check owner.")
	}
	if kind != "hostedzone" {
		return Zone{}, failure("InvalidInput", "ResourceType must be hostedzone or healthcheck.")
	}
	return s.zone(tx, id, op)
}

func zoneTagSet(z Zone) *api.ResourceTagSet {
	out := &api.ResourceTagSet{ResourceId: new(api.TagResourceId(z.ID)), ResourceType: new(api.TagResourceTypeHostedzone), Tags: api.TagList{}}
	keys := make([]string, 0, len(z.Tags))
	for key := range z.Tags {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	for _, key := range keys {
		out.Tags = append(out.Tags, api.Tag{Key: new(api.TagKey(key)), Value: new(api.TagValue(z.Tags[key]))})
	}
	return out
}

func validTagKey(key string) bool {
	return key != "" && utf8.ValidString(key) && utf8.RuneCountInString(key) <= 128 && !strings.HasPrefix(strings.ToLower(key), "aws:")
}

func (s *Service) changeTagsForResource(tx Transaction, in *api.ChangeTagsForResourceRequest) (*api.ChangeTagsForResourceResponse, error) {
	z, err := s.taggedZone(tx, value(in.ResourceType), value(in.ResourceId), "ChangeTagsForResource")
	if err != nil {
		return nil, err
	}
	if len(in.AddTags) > 10 || len(in.RemoveTagKeys) > 10 {
		return nil, failure("InvalidInput", "At most 10 tags or removal keys are allowed per request.")
	}
	tags := z.Tags
	if tags == nil && len(in.AddTags) != 0 {
		tags = make(map[string]string, len(in.AddTags))
	}
	for _, key := range in.RemoveTagKeys {
		if !validTagKey(string(key)) {
			return nil, failure("InvalidInput", "Invalid tag key.")
		}
		delete(tags, string(key))
	}
	seen := make(map[string]bool, len(in.AddTags))
	for _, tag := range in.AddTags {
		key, v := value(tag.Key), value(tag.Value)
		if !validTagKey(key) || !utf8.ValidString(v) || utf8.RuneCountInString(v) > 256 || seen[key] {
			return nil, failure("InvalidInput", "Invalid or duplicate tag.")
		}
		seen[key] = true
		tags[key] = v
	}
	if len(tags) > 10 {
		return nil, failure("InvalidInput", "A hosted zone can have at most 10 tags.")
	}
	z.Tags = tags
	if err := tx.PutZone(z); err != nil {
		return nil, err
	}
	return &api.ChangeTagsForResourceResponse{}, nil
}

func (s *Service) listTagsForResource(tx Transaction, in *api.ListTagsForResourceRequest) (*api.ListTagsForResourceResponse, error) {
	z, err := s.taggedZone(tx, value(in.ResourceType), value(in.ResourceId), "ListTagsForResource")
	if err != nil {
		return nil, err
	}
	return &api.ListTagsForResourceResponse{ResourceTagSet: zoneTagSet(z)}, nil
}

func (s *Service) listTagsForResources(tx Transaction, in *api.ListTagsForResourcesRequest) (*api.ListTagsForResourcesResponse, error) {
	if len(in.ResourceIds) < 1 || len(in.ResourceIds) > 10 {
		return nil, failure("InvalidInput", "Provide 1 through 10 resource IDs.")
	}
	out := &api.ListTagsForResourcesResponse{ResourceTagSets: api.ResourceTagSetList{}}
	for _, id := range in.ResourceIds {
		z, err := s.taggedZone(tx, value(in.ResourceType), string(id), "ListTagsForResources")
		if err != nil {
			return nil, err
		}
		out.ResourceTagSets = append(out.ResourceTagSets, *zoneTagSet(z))
	}
	return out, nil
}
