package wafv2

import (
	"context"
	"errors"
	"maps"
	"slices"
	"strings"

	api "stackd/internal/awsapi/wafv2"
)

func registerTags(s *Service) {
	register(s, "TagResource", s.tagResource)
	register(s, "UntagResource", s.untagResource)
	register(s, "ListTagsForResource", s.listTags)
}

// taggable resolves a web ACL or IP set ARN. Tags remain owned by the entity
// row, so tagging participates in the same optimistic transaction.
type taggable struct {
	webACL *WebACL
	ipSet  *IPSet
}

func (v taggable) arn() string {
	if v.webACL != nil {
		return v.webACL.ARN
	}
	return v.ipSet.ARN
}
func (v taggable) tags() map[string]string {
	if v.webACL != nil {
		return v.webACL.Tags
	}
	return v.ipSet.Tags
}

func (s *Service) loadTaggable(ctx context.Context, r Reader, arn, action string) (taggable, error) {
	sc := scopeFor(ctx)
	var out taggable
	if name, id, ok := parseEntityARN(sc, arn, "webacl"); ok {
		v, err := r.WebACL(sc, webACLARN(sc, name, id))
		if err != nil {
			return out, tagMissing(err)
		}
		out.webACL = &v
	} else if name, id, ok := parseEntityARN(sc, arn, "ipset"); ok {
		v, err := r.IPSet(sc, ipSetARN(sc, name, id))
		if err != nil {
			return out, tagMissing(err)
		}
		out.ipSet = &v
	} else {
		return out, invalidParameter("RESOURCE_ARN", arn, "Tagging supports REGIONAL web ACL and IP set ARNs in this account and Region")
	}
	if err := s.authorize(ctx, "wafv2:"+action, out.arn(), out.tags(), nil); err != nil {
		return out, err
	}
	if out.webACL != nil {
		return out, checkResourceOwner(ctx, out.webACL.Owner)
	}
	return out, checkResourceOwner(ctx, out.ipSet.Owner)
}

func tagMissing(err error) error {
	if errors.Is(err, ErrNotFound) {
		return nonexistent("AWS WAF couldn’t find the tagged resource")
	}
	return err
}

func (s *Service) storeTags(t Transaction, v taggable, tags map[string]string) error {
	if len(tags) > 50 {
		return failure("WAFLimitsExceededException", "A resource can have at most 50 tags", 400)
	}
	if v.webACL != nil {
		v.webACL.Tags = tags
		return t.PutWebACL(*v.webACL)
	}
	v.ipSet.Tags = tags
	return t.PutIPSet(*v.ipSet)
}

func (s *Service) tagResource(ctx context.Context, t Transaction, in *api.TagResourceInput) (*api.TagResourceOutput, error) {
	added, conditions, err := requestTags(in.Tags)
	if err != nil {
		return nil, err
	}
	if len(added) == 0 {
		return nil, invalidParameter("TAGS", "Tags", "Tags must contain at least one tag")
	}
	v, err := s.loadTaggable(ctx, t, value(in.ResourceARN), "TagResource")
	if err != nil {
		return nil, err
	}
	if err := s.authorize(ctx, "wafv2:TagResource", v.arn(), v.tags(), conditions); err != nil {
		return nil, err
	}
	tags := maps.Clone(v.tags())
	if tags == nil {
		tags = map[string]string{}
	}
	maps.Copy(tags, added)
	return &api.TagResourceOutput{}, s.storeTags(t, v, tags)
}

func (s *Service) untagResource(ctx context.Context, t Transaction, in *api.UntagResourceInput) (*api.UntagResourceOutput, error) {
	if len(in.TagKeys) == 0 {
		return nil, invalidParameter("TAG_KEYS", "TagKeys", "TagKeys must contain at least one key")
	}
	v, err := s.loadTaggable(ctx, t, value(in.ResourceARN), "UntagResource")
	if err != nil {
		return nil, err
	}
	keys := make([]string, 0, len(in.TagKeys))
	for _, k := range in.TagKeys {
		keys = append(keys, string(k))
	}
	if err := s.authorize(ctx, "wafv2:UntagResource", v.arn(), v.tags(), map[string][]string{"aws:TagKeys": keys}); err != nil {
		return nil, err
	}
	tags := maps.Clone(v.tags())
	for _, k := range keys {
		delete(tags, k)
	}
	return &api.UntagResourceOutput{}, s.storeTags(t, v, tags)
}

func (s *Service) listTags(ctx context.Context, t Transaction, in *api.ListTagsForResourceInput) (*api.ListTagsForResourceOutput, error) {
	v, err := s.loadTaggable(ctx, t, value(in.ResourceARN), "ListTagsForResource")
	if err != nil {
		return nil, err
	}
	keys := slices.SortedFunc(maps.Keys(v.tags()), strings.Compare)
	start, end, next, err := page(in.Limit, in.NextMarker, len(keys))
	if err != nil {
		return nil, err
	}
	info := &api.TagInfoForResource{ResourceARN: new(api.ResourceArn(v.arn())), TagList: api.TagList{}}
	for _, k := range keys[start:end] {
		info.TagList = append(info.TagList, api.Tag{Key: new(api.TagKey(k)), Value: new(api.TagValue(v.tags()[k]))})
	}
	return &api.ListTagsForResourceOutput{TagInfoForResource: info, NextMarker: next}, nil
}
