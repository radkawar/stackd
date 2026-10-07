package identitycenter

import (
	api "stackd/internal/awsapi/ssoadmin"
	"strings"
)

func (s *Service) registerTags() {
	register(s, "ssoadmin", "ListTagsForResource", func(tx Transaction, in *api.ListTagsForResourceInput) (*api.ListTagsForResourceOutput, error) {
		tags, _, e := s.tagResource(tx, value(in.InstanceArn), value(in.ResourceArn), "ListTagsForResource", nil)
		if e != nil {
			return nil, e
		}
		rows, next, e := pageSlice(wireTags(tags), value(in.NextToken), "ListTagsForResource/"+value(in.ResourceArn), 100, func(v api.Tag) string { return value(v.Key) })
		if e != nil {
			return nil, e
		}
		out := &api.ListTagsForResourceOutput{Tags: rows}
		if next != "" {
			out.NextToken = new(api.Token(next))
		}
		return out, nil
	})
	register(s, "ssoadmin", "TagResource", func(tx Transaction, in *api.TagResourceInput) (*api.TagResourceOutput, error) {
		add, e := parseTags(in.Tags)
		if e != nil {
			return nil, e
		}
		tags, save, e := s.tagResource(tx, value(in.InstanceArn), value(in.ResourceArn), "TagResource", add)
		if e != nil {
			return nil, e
		}
		for k, v := range add {
			tags[k] = v
		}
		if len(tags) > 50 {
			return nil, bad("A resource can have at most 50 tags.")
		}
		return &api.TagResourceOutput{}, save(tags)
	})
	register(s, "ssoadmin", "UntagResource", func(tx Transaction, in *api.UntagResourceInput) (*api.UntagResourceOutput, error) {
		keys := map[string]string{}
		for _, key := range in.TagKeys {
			keys[string(key)] = ""
		}
		tags, save, e := s.tagResource(tx, value(in.InstanceArn), value(in.ResourceArn), "UntagResource", keys)
		if e != nil {
			return nil, e
		}
		for key := range keys {
			if strings.HasPrefix(strings.ToLower(key), "aws:") {
				return nil, bad("Reserved tags cannot be removed.")
			}
			delete(tags, key)
		}
		return &api.UntagResourceOutput{}, save(tags)
	})
}
func (s *Service) tagResource(tx Transaction, instance, arn, action string, requested map[string]string) (map[string]string, func(map[string]string) error, error) {
	if strings.Contains(arn, ":instance/") {
		v, e := tx.Instance(arn)
		if e != nil {
			return nil, nil, e
		}
		if v.Scope != scopeFor(tx.Context()) || (instance != "" && instance != arn) {
			return nil, nil, ErrNotFound
		}
		if e = s.authorizeTags(tx.Context(), action, arn, v.Tags, requested); e != nil {
			return nil, nil, e
		}
		if e = claimCheck(tx.Context(), v.CloudFormationOwner, action); e != nil {
			return nil, nil, e
		}
		return v.Tags, func(tags map[string]string) error { v.Tags = tags; return tx.PutInstance(v) }, nil
	}
	p, e := tx.PermissionSet(arn)
	if e != nil {
		return nil, nil, e
	}
	v, e := tx.Instance(p.InstanceARN)
	if e != nil {
		return nil, nil, e
	}
	if v.Scope != scopeFor(tx.Context()) || (instance != "" && instance != p.InstanceARN) {
		return nil, nil, ErrNotFound
	}
	if e = s.authorizeTags(tx.Context(), action, arn, p.Tags, requested); e != nil {
		return nil, nil, e
	}
	if e = claimCheck(tx.Context(), p.CloudFormationOwner, action); e != nil {
		return nil, nil, e
	}
	return p.Tags, func(tags map[string]string) error { p.Tags = tags; return tx.PutPermissionSet(p) }, nil
}
