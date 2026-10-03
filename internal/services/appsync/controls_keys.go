package appsync

import (
	"context"
	"maps"
	api "stackd/internal/awsapi/appsync"
	"strings"
	"time"
)

func registerKeys(s *Service) {
	register(s, "CreateApiKey", func(ctx context.Context, t Transaction, in *api.CreateApiKeyRequest) (*api.CreateApiKeyResponse, error) {
		p, e := s.load(ctx, t, value(in.ApiId), "CreateApiKey")
		if e != nil {
			return nil, e
		}
		keys, e := s.retainedKeys(t, p.Key)
		if e != nil {
			return nil, e
		}
		if len(keys) >= 50 {
			return nil, failure("ApiKeyLimitExceededException", "API key limit exceeded.", 400)
		}
		key := api.ApiKey{Description: in.Description}
		text(&key.Id, "da2-"+randomID())
		if e = s.expiration(&key, in.Expires); e != nil {
			return nil, e
		}
		if e = t.PutAPIKey(APIKeyRecord{p.Key, key}); e != nil {
			return nil, e
		}
		return &api.CreateApiKeyResponse{ApiKey: &key}, nil
	})
	register(s, "UpdateApiKey", func(ctx context.Context, t Transaction, in *api.UpdateApiKeyRequest) (*api.UpdateApiKeyResponse, error) {
		p, e := s.load(ctx, t, value(in.ApiId), "UpdateApiKey")
		if e != nil {
			return nil, e
		}
		keys, e := s.retainedKeys(t, p.Key)
		if e != nil {
			return nil, e
		}
		for _, r := range keys {
			if value(r.Key.Id) == value(in.Id) {
				if in.Description != nil {
					r.Key.Description = in.Description
				}
				if in.Expires != nil && *in.Expires != 0 {
					if e = s.expiration(&r.Key, in.Expires); e != nil {
						return nil, e
					}
				}
				if e = t.PutAPIKey(r); e != nil {
					return nil, e
				}
				return &api.UpdateApiKeyResponse{ApiKey: &r.Key}, nil
			}
		}
		return nil, ErrNotFound
	})
	register(s, "DeleteApiKey", func(ctx context.Context, t Transaction, in *api.DeleteApiKeyRequest) (*api.DeleteApiKeyResponse, error) {
		p, e := s.load(ctx, t, value(in.ApiId), "DeleteApiKey")
		if e != nil {
			return nil, e
		}
		return &api.DeleteApiKeyResponse{}, t.DeleteAPIKey(p.Key, value(in.Id))
	})
	register(s, "ListApiKeys", func(ctx context.Context, t Transaction, in *api.ListApiKeysRequest) (*api.ListApiKeysResponse, error) {
		p, e := s.load(ctx, t, value(in.ApiId), "ListApiKeys")
		if e != nil {
			return nil, e
		}
		keys, e := s.retainedKeys(t, p.Key)
		if e != nil {
			return nil, e
		}
		out := api.ApiKeys{}
		for _, r := range keys {
			out = append(out, r.Key)
		}
		out, next, e := page(out, in.NextToken, in.MaxResults, p.Key.ARN()+"/ListApiKeys", func(k api.ApiKey) string { return value(k.Id) })
		return &api.ListApiKeysResponse{ApiKeys: out, NextToken: next}, e
	})
}

// AWS da2 keys round expiration to hours and remain renewable for sixty days.
// https://docs.aws.amazon.com/appsync/latest/APIReference/API_ApiKey.html
func (s *Service) expiration(key *api.ApiKey, requested *api.Long) error {
	now := s.clock.Now()
	expires := now.Add(7 * 24 * time.Hour).Unix()
	if requested != nil && *requested != 0 {
		expires = int64(*requested)
	}
	if expires < now.Add(24*time.Hour).Unix() || expires > now.Add(365*24*time.Hour).Unix() {
		return failure("ApiKeyValidityOutOfBoundsException", "API key expiration must be between 1 and 365 days from creation or update.", 400)
	}
	expiry := api.Long(expires - expires%3600)
	deletes := expiry + 60*24*3600
	key.Expires = &expiry
	key.Deletes = &deletes
	return nil
}
func (s *Service) retainedKeys(t Transaction, k Key) ([]APIKeyRecord, error) {
	keys, e := t.APIKeys(k)
	if e != nil {
		return nil, e
	}
	out := keys[:0]
	for _, key := range keys {
		if key.Key.Deletes != nil && int64(*key.Key.Deletes) <= s.clock.Now().Unix() {
			if e = t.DeleteAPIKey(k, value(key.Key.Id)); e != nil {
				return nil, e
			}
		} else {
			out = append(out, key)
		}
	}
	return out, nil
}

func registerTags(s *Service) {
	register(s, "ListTagsForResource", func(ctx context.Context, t Transaction, in *api.ListTagsForResourceRequest) (*api.ListTagsForResourceResponse, error) {
		p, e := s.taggedAPI(ctx, t, value(in.ResourceArn), "ListTagsForResource")
		if e != nil {
			return nil, e
		}
		return &api.ListTagsForResourceResponse{Tags: p.API.Tags}, nil
	})
	register(s, "TagResource", func(ctx context.Context, t Transaction, in *api.TagResourceRequest) (*api.TagResourceResponse, error) {
		p, e := s.taggedAPI(ctx, t, value(in.ResourceArn), "")
		if e != nil {
			return nil, e
		}
		if e = validateTags(in.Tags); e != nil {
			return nil, e
		}
		if e = s.permissionContext(ctx, "TagResource", p.Key.ARN(), tagConditions(p.API.Tags, in.Tags, nil)); e != nil {
			return nil, e
		}
		if p.API.Tags == nil {
			p.API.Tags = api.TagMap{}
		}
		maps.Copy(p.API.Tags, in.Tags)
		if e = validateTags(p.API.Tags); e != nil {
			return nil, e
		}
		return &api.TagResourceResponse{}, t.PutAPI(p)
	})
	register(s, "UntagResource", func(ctx context.Context, t Transaction, in *api.UntagResourceRequest) (*api.UntagResourceResponse, error) {
		p, e := s.taggedAPI(ctx, t, value(in.ResourceArn), "")
		if e != nil {
			return nil, e
		}
		if e = s.permissionContext(ctx, "UntagResource", p.Key.ARN(), tagConditions(p.API.Tags, nil, in.TagKeys)); e != nil {
			return nil, e
		}
		for _, key := range in.TagKeys {
			if strings.HasPrefix(strings.ToLower(string(key)), "aws:") {
				return nil, bad("Reserved tag key.")
			}
			delete(p.API.Tags, key)
		}
		return &api.UntagResourceResponse{}, t.PutAPI(p)
	})
}
func (s *Service) taggedAPI(ctx context.Context, r Reader, arn, action string) (APIRecord, error) {
	prefix := keyFor(ctx, "").ARN()
	if !strings.HasPrefix(arn, prefix) || strings.Contains(strings.TrimPrefix(arn, prefix), "/") {
		return APIRecord{}, ErrNotFound
	}
	k := keyFor(ctx, strings.TrimPrefix(arn, prefix))
	p, e := r.API(k)
	if e != nil {
		return p, e
	}
	if action != "" {
		e = s.permission(ctx, action, arn, p.API.Tags)
	}
	return p, e
}
func validateTags(tags api.TagMap) error {
	if len(tags) > 50 {
		return bad("A resource supports at most 50 tags.")
	}
	for k, v := range tags {
		if len(k) < 1 || len(k) > 128 || len(v) > 256 || strings.HasPrefix(strings.ToLower(string(k)), "aws:") {
			return bad("Invalid or reserved tag.")
		}
	}
	return nil
}
func tagConditions(existing, requested api.TagMap, keys api.TagKeyList) map[string][]string {
	c := map[string][]string{}
	for k, v := range existing {
		c["aws:ResourceTag/"+string(k)] = []string{string(v)}
	}
	for k, v := range requested {
		c["aws:RequestTag/"+string(k)] = []string{string(v)}
		keys = append(keys, k)
	}
	for _, k := range keys {
		c["aws:TagKeys"] = append(c["aws:TagKeys"], string(k))
	}
	return c
}
