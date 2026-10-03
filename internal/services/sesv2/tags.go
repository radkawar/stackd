package sesv2

import (
	"context"
	"slices"
	api "stackd/internal/awsapi/sesv2"
	tagging "stackd/internal/services/resourcegroupstaggingapi"
	"strings"
)

func parseTags(tags api.TagList) (map[string]string, error) {
	out := map[string]string{}
	for _, t := range tags {
		k, v := value(t.Key), value(t.Value)
		if k == "" || len(k) > 128 || len(v) > 256 || strings.HasPrefix(strings.ToLower(k), "aws:") {
			return nil, bad("Invalid resource tag.")
		}
		if _, ok := out[k]; ok {
			return nil, bad("Duplicate tag key.")
		}
		out[k] = v
	}
	if len(out) > 50 {
		return nil, bad("Too many tags.")
	}
	return out, nil
}
func apiTags(tags map[string]string) api.TagList {
	keys := make([]string, 0, len(tags))
	for k := range tags {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	out := api.TagList{}
	for _, k := range keys {
		out = append(out, api.Tag{Key: new(api.TagKey(k)), Value: new(api.TagValue(tags[k]))})
	}
	return out
}
func tagConditions(tags map[string]string) map[string][]string {
	out := map[string][]string{}
	var keys []string
	for k, v := range tags {
		out["aws:RequestTag/"+k] = []string{v}
		keys = append(keys, k)
	}
	out["aws:TagKeys"] = keys
	return out
}
func tagTarget(tx Transaction, arn string) (map[string]string, func(map[string]string) error, error) {
	scope := scopeFor(tx.Context())
	prefix := "arn:" + scope.Partition + ":ses:" + scope.Region + ":" + scope.AccountID + ":"
	if !strings.HasPrefix(arn, prefix) {
		return nil, nil, ErrNotFound
	}
	kind, name, ok := strings.Cut(strings.TrimPrefix(arn, prefix), "/")
	if !ok {
		return nil, nil, bad("Invalid resource ARN.")
	}
	k := ResourceKey{scope, name}
	switch kind {
	case "identity":
		v, e := tx.Identity(k)
		return v.Tags, func(tags map[string]string) error { v.Tags = tags; return tx.PutIdentity(v) }, e
	case "configuration-set":
		v, e := tx.ConfigurationSet(k)
		return v.Tags, func(tags map[string]string) error { v.Tags = tags; return tx.PutConfigurationSet(v) }, e
	default:
		return nil, nil, unsupported("Tagging is implemented for email identities and configuration sets.")
	}
}
func (s *Service) tagResource(tx Transaction, in *api.TagResourceInput) (*api.TagResourceOutput, error) {
	tags, e := parseTags(in.Tags)
	if e != nil {
		return nil, e
	}
	arn := value(in.ResourceArn)
	current, put, e := tagTarget(tx, arn)
	if e != nil {
		return nil, e
	}
	if e = s.authorize(tx, "TagResource", arn, current, tagConditions(tags)); e != nil {
		return nil, e
	}
	for k, v := range tags {
		current[k] = v
	}
	if len(current) > 50 {
		return nil, bad("Too many tags.")
	}
	return &api.TagResourceOutput{}, put(current)
}
func (s *Service) untagResource(tx Transaction, in *api.UntagResourceInput) (*api.UntagResourceOutput, error) {
	arn := value(in.ResourceArn)
	current, put, e := tagTarget(tx, arn)
	if e != nil {
		return nil, e
	}
	var keys []string
	if len(in.TagKeys) != 0 {
		keys = make([]string, len(in.TagKeys))
	}
	for i, k := range in.TagKeys {
		keys[i] = string(k)
	}
	if e = s.authorize(tx, "UntagResource", arn, current, map[string][]string{"aws:TagKeys": keys}); e != nil {
		return nil, e
	}
	for _, k := range keys {
		delete(current, k)
	}
	return &api.UntagResourceOutput{}, put(current)
}
func (s *Service) listTags(tx Transaction, in *api.ListTagsForResourceInput) (*api.ListTagsForResourceOutput, error) {
	arn := value(in.ResourceArn)
	tags, _, e := tagTarget(tx, arn)
	if e != nil {
		return nil, e
	}
	if e = s.authorize(tx, "ListTagsForResource", arn, tags, nil); e != nil {
		return nil, e
	}
	return &api.ListTagsForResourceOutput{Tags: apiTags(tags)}, nil
}

// ListTaggingResources is trusted owner discovery; native mutations still enforce SES IAM.
func (s *Service) ListTaggingResources(ctx context.Context) ([]tagging.Resource, error) {
	out := []tagging.Resource{}
	e := s.repository.View(ctx, func(r Reader) error {
		scope := scopeFor(ctx)
		ids, e := r.Identities(scope)
		if e != nil {
			return e
		}
		for _, v := range ids {
			out = append(out, tagging.Resource{ARN: v.Key.ARN("identity"), ResourceType: "ses:identity", Tags: v.Tags})
		}
		sets, e := r.ConfigurationSets(scope)
		if e != nil {
			return e
		}
		for _, v := range sets {
			out = append(out, tagging.Resource{ARN: v.Key.ARN("configuration-set"), ResourceType: "ses:configuration-set", Tags: v.Tags})
		}
		return nil
	})
	return out, e
}
