package ssm

import (
	"errors"
	"maps"
	"regexp"
	"slices"
	"strings"
	"unicode/utf8"

	api "stackd/internal/awsapi/ssm"
)

var tagCharacters = regexp.MustCompile(`^[\p{L}\p{Z}\p{N}_.:/=+\-@]*$`)

func validateTagKey(key string) error {
	if n := utf8.RuneCountInString(key); n < 1 || n > 128 || !tagCharacters.MatchString(key) || strings.HasPrefix(strings.ToLower(key), "aws:") {
		return failure("ValidationException", "Tag keys must have 1-128 supported characters and cannot begin with aws:.")
	}
	return nil
}

func validateTags(tags api.TagList) (map[string]string, error) {
	result := make(map[string]string, len(tags))
	for _, tag := range tags {
		key, v := value(tag.Key), value(tag.Value)
		if err := validateTagKey(key); err != nil {
			return nil, err
		}
		if tag.Value == nil || utf8.RuneCountInString(v) > 256 || !tagCharacters.MatchString(v) {
			return nil, failure("ValidationException", "Tag values must have 0-256 supported characters.")
		}
		result[key] = v
	}
	if len(result) > 50 {
		return nil, failure("TooManyTagsError", "A parameter can have at most 50 tags.")
	}
	return result, nil
}

func tagConditions(tags map[string]string) map[string][]string {
	conditions := make(map[string][]string, len(tags)+1)
	keys := slices.Sorted(maps.Keys(tags))
	conditions["aws:TagKeys"] = keys
	for _, key := range keys {
		conditions["aws:RequestTag/"+key] = []string{tags[key]}
	}
	return conditions
}

func (s *Service) tagParameter(tx Transaction, kind, name, action string, conditions map[string][]string) (ParameterRecord, error) {
	if kind != "Parameter" {
		return ParameterRecord{}, failure("UnsupportedOperation", "Only Parameter resources are supported by Parameter Store tagging.")
	}
	key, err := parameterKey(tx.Context(), name, false)
	if err != nil {
		return ParameterRecord{}, failure("InvalidResourceId", "The parameter resource ID is not valid.")
	}
	p, err := resolveParameter(tx, key)
	if errors.Is(err, ErrNotFound) {
		return ParameterRecord{}, failure("InvalidResourceId", "The parameter resource could not be found.")
	}
	if err != nil {
		return ParameterRecord{}, err
	}
	if err := s.authorize(tx, action, p, conditions); err != nil {
		return ParameterRecord{}, err
	}
	return p, nil
}

func (s *Service) addTagsToResource(tx Transaction, in *api.AddTagsToResourceRequest) (*api.AddTagsToResourceResult, error) {
	tags, err := validateTags(in.Tags)
	if err != nil {
		return nil, err
	}
	p, err := s.tagParameter(tx, value(in.ResourceType), value(in.ResourceId), "AddTagsToResource", tagConditions(tags))
	if err != nil {
		return nil, err
	}
	if p.Tags == nil {
		p.Tags = make(map[string]string, len(tags))
	}
	maps.Copy(p.Tags, tags)
	if len(p.Tags) > 50 {
		return nil, failure("TooManyTagsError", "A parameter can have at most 50 tags.")
	}
	return &api.AddTagsToResourceResult{}, tx.PutParameter(p)
}

func (s *Service) removeTagsFromResource(tx Transaction, in *api.RemoveTagsFromResourceRequest) (*api.RemoveTagsFromResourceResult, error) {
	var keys []string
	if len(in.TagKeys) != 0 {
		keys = make([]string, 0, len(in.TagKeys))
	}
	for _, key := range in.TagKeys {
		if err := validateTagKey(string(key)); err != nil {
			return nil, err
		}
		keys = append(keys, string(key))
	}
	p, err := s.tagParameter(tx, value(in.ResourceType), value(in.ResourceId), "RemoveTagsFromResource", map[string][]string{"aws:TagKeys": keys})
	if err != nil {
		return nil, err
	}
	for _, key := range keys {
		delete(p.Tags, key)
	}
	return &api.RemoveTagsFromResourceResult{}, tx.PutParameter(p)
}

func (s *Service) listTagsForResource(tx Transaction, in *api.ListTagsForResourceRequest) (*api.ListTagsForResourceResult, error) {
	p, err := s.tagParameter(tx, value(in.ResourceType), value(in.ResourceId), "ListTagsForResource", nil)
	if err != nil {
		return nil, err
	}
	out := &api.ListTagsForResourceResult{TagList: make(api.TagList, 0, len(p.Tags))}
	for _, key := range slices.Sorted(maps.Keys(p.Tags)) {
		out.TagList = append(out.TagList, api.Tag{Key: new(api.TagKey(key)), Value: new(api.TagValue(p.Tags[key]))})
	}
	return out, nil
}
