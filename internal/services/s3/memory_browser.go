package s3

import (
	"slices"

	"stackd/storage/memory"
)

func copyOptional[T any](v *T) *T {
	if v == nil {
		return nil
	}
	return new(*v)
}

func cloneCORS(rules []CORSRule) []CORSRule {
	out := slices.Clone(rules)
	for i := range out {
		v := &out[i]
		v.ID = copyOptional(v.ID)
		v.MaxAgeSeconds = copyOptional(v.MaxAgeSeconds)
		v.AllowedOrigins = slices.Clone(v.AllowedOrigins)
		v.AllowedMethods = slices.Clone(v.AllowedMethods)
		v.AllowedHeaders = slices.Clone(v.AllowedHeaders)
		v.ExposeHeaders = slices.Clone(v.ExposeHeaders)
	}
	return out
}

func cloneWebsite(v *WebsiteConfiguration) *WebsiteConfiguration {
	if v == nil {
		return nil
	}
	out := *v
	out.IndexSuffix = copyOptional(v.IndexSuffix)
	out.ErrorKey = copyOptional(v.ErrorKey)
	if v.RedirectAll != nil {
		redirect := *v.RedirectAll
		redirect.Protocol = copyOptional(redirect.Protocol)
		out.RedirectAll = &redirect
	}
	out.Rules = slices.Clone(v.Rules)
	for i := range out.Rules {
		rule := &out.Rules[i]
		if rule.Condition != nil {
			condition := *rule.Condition
			condition.KeyPrefix = copyOptional(condition.KeyPrefix)
			condition.ErrorCode = copyOptional(condition.ErrorCode)
			rule.Condition = &condition
		}
		rule.Redirect.HostName = copyOptional(rule.Redirect.HostName)
		rule.Redirect.Protocol = copyOptional(rule.Redirect.Protocol)
		rule.Redirect.StatusCode = copyOptional(rule.Redirect.StatusCode)
		rule.Redirect.ReplaceKeyPrefix = copyOptional(rule.Redirect.ReplaceKeyPrefix)
		rule.Redirect.ReplaceKey = copyOptional(rule.Redirect.ReplaceKey)
	}
	return &out
}

func (r memoryReader) BucketCORS(key BucketKey) ([]CORSRule, error) {
	var out []CORSRule
	err := r.repository.cors.View(r.Context(), func(state *map[BucketKey][]CORSRule, _ *memory.Transaction) error {
		out = cloneCORS((*state)[key])
		return nil
	})
	return out, err
}

func (w memoryWriter) ReplaceBucketCORS(key BucketKey, rules []CORSRule) error {
	return w.repository.cors.Update(w.Context(), func(state *map[BucketKey][]CORSRule, _ *memory.Transaction) error {
		if len(rules) == 0 {
			delete(*state, key)
		} else {
			(*state)[key] = cloneCORS(rules)
		}
		return nil
	})
}

func (r memoryReader) BucketWebsite(key BucketKey) (*WebsiteConfiguration, error) {
	var out *WebsiteConfiguration
	err := r.repository.websites.View(r.Context(), func(state *map[BucketKey]WebsiteConfiguration, _ *memory.Transaction) error {
		if v, ok := (*state)[key]; ok {
			out = cloneWebsite(&v)
		}
		return nil
	})
	return out, err
}

func (w memoryWriter) ReplaceBucketWebsite(key BucketKey, config *WebsiteConfiguration) error {
	return w.repository.websites.Update(w.Context(), func(state *map[BucketKey]WebsiteConfiguration, _ *memory.Transaction) error {
		if config == nil {
			delete(*state, key)
		} else {
			(*state)[key] = *cloneWebsite(config)
		}
		return nil
	})
}
