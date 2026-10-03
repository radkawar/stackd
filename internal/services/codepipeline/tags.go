package codepipeline

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"slices"
	api "stackd/internal/awsapi/codepipeline"
	"strconv"
	"strings"
)

func tagMap(tags api.TagList) (map[string]string, error) {
	out := map[string]string{}
	for _, t := range tags {
		k := text(t.Key)
		if k == "" || len(k) > 128 || len(text(t.Value)) > 256 || strings.HasPrefix(strings.ToLower(k), "aws:") {
			return nil, failure("InvalidTagsException", "Invalid tag")
		}
		if _, ok := out[k]; ok {
			return nil, failure("InvalidTagsException", "Duplicate tag key")
		}
		out[k] = text(t.Value)
	}
	if len(out) > 50 {
		return nil, failure("TooManyTagsException", "At most 50 tags are allowed")
	}
	return out, nil
}
func tagList(tags map[string]string) api.TagList {
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
func addRequestTags(out map[string][]string, input any) {
	var tags api.TagList
	var keys []string
	switch in := input.(type) {
	case *api.CreatePipelineInput:
		tags = in.Tags
	case *api.TagResourceInput:
		tags = in.Tags
	case *api.UntagResourceInput:
		for _, k := range in.TagKeys {
			keys = append(keys, string(k))
		}
	}
	for _, t := range tags {
		k := text(t.Key)
		out["aws:RequestTag/"+k] = []string{text(t.Value)}
		keys = append(keys, k)
	}
	if keys != nil {
		out["aws:TagKeys"] = keys
	}
}
func (s *Service) tagPipeline(tx Transaction, action, arn string) (Pipeline, error) {
	sc := scopeFor(tx.Context())
	prefix := ARN(sc, "")
	if !strings.HasPrefix(arn, prefix) {
		if err := s.authorize(tx.Context(), action, arn, nil); err != nil {
			return Pipeline{}, err
		}
		return Pipeline{}, failure("ResourceNotFoundException", "Resource not found")
	}
	return s.pipelineFor(tx, action, strings.TrimPrefix(arn, prefix))
}
func registerTags(s *Service) {
	register(s, "TagResource", func(tx Transaction, in *api.TagResourceInput) (*api.TagResourceOutput, error) {
		v, err := s.tagPipeline(tx, "TagResource", text(in.ResourceArn))
		if err != nil {
			return nil, err
		}
		tags, err := tagMap(in.Tags)
		if err != nil {
			return nil, err
		}
		for k, x := range tags {
			v.Tags[k] = x
		}
		if len(v.Tags) > 50 {
			return nil, failure("TooManyTagsException", "At most 50 tags are allowed")
		}
		if err = tx.PutPipeline(v); err != nil {
			return nil, err
		}
		return &api.TagResourceOutput{}, nil
	})
	register(s, "UntagResource", func(tx Transaction, in *api.UntagResourceInput) (*api.UntagResourceOutput, error) {
		v, err := s.tagPipeline(tx, "UntagResource", text(in.ResourceArn))
		if err != nil {
			return nil, err
		}
		for _, k := range in.TagKeys {
			delete(v.Tags, string(k))
		}
		if err = tx.PutPipeline(v); err != nil {
			return nil, err
		}
		return &api.UntagResourceOutput{}, nil
	})
	register(s, "ListTagsForResource", func(tx Transaction, in *api.ListTagsForResourceInput) (*api.ListTagsForResourceOutput, error) {
		v, err := s.tagPipeline(tx, "ListTagsForResource", text(in.ResourceArn))
		if err != nil {
			return nil, err
		}
		tags := tagList(v.Tags)
		start, end, next, err := page(v.Scope, "tags:"+v.Incarnation, text(in.NextToken), int(value(in.MaxResults)), len(tags))
		if err != nil {
			return nil, err
		}
		return &api.ListTagsForResourceOutput{Tags: tags[start:end], NextToken: next}, nil
	})
}
func page(sc Scope, query, token string, max, total int) (int, int, *api.NextToken, error) {
	if max == 0 {
		max = 100
	}
	if max < 1 || max > 1000 {
		return 0, 0, nil, failure("ValidationException", "Invalid maximum results")
	}
	sum := sha256.Sum256([]byte(fmt.Sprint(sc) + "/" + query))
	key := hex.EncodeToString(sum[:])
	start := 0
	if token != "" {
		raw, err := base64.RawURLEncoding.DecodeString(token)
		parts := strings.Split(string(raw), ":")
		if err != nil || len(parts) != 2 || parts[0] != key {
			return 0, 0, nil, failure("InvalidNextTokenException", "Invalid pagination token")
		}
		start, err = strconv.Atoi(parts[1])
		if err != nil || start < 0 || start > total {
			return 0, 0, nil, failure("InvalidNextTokenException", "Invalid pagination offset")
		}
	}
	end := min(start+max, total)
	var next *api.NextToken
	if end < total {
		next = new(api.NextToken(base64.RawURLEncoding.EncodeToString([]byte(key + ":" + strconv.Itoa(end)))))
	}
	return start, end, next, nil
}
