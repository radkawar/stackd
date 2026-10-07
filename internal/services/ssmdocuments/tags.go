package ssmdocuments

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
		return nil, failure("TooManyTagsError", "A document can have at most 50 tags.")
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

func (s *Service) tagDocument(tx Transaction, kind, name, action string, conditions map[string][]string) (Record, error) {
	if kind != "Document" {
		return Record{}, failure("UnsupportedOperation", "Only Document resources are supported by SSM document tagging.")
	}
	key, err := documentKey(tx.Context(), name)
	builtin := key.AccountID == "" && key.Name == "AWS-RunShellScript"
	if err != nil || (key.AccountID != scopeFor(tx.Context()).AccountID && !builtin) {
		return Record{}, failure("InvalidResourceId", "The document resource ID is not valid.")
	}
	record, err := loadRecord(tx, key)
	if err != nil {
		record = Record{Key: key}
	}
	if rejected := s.authorize(tx, action, record, conditions); rejected != nil {
		return Record{}, rejected
	}
	if errors.Is(err, ErrNotFound) || (err == nil && key.AccountID == "" && action != "ListTagsForResource") {
		return Record{}, failure("InvalidResourceId", "The document resource does not exist or cannot be tagged.")
	}
	if err != nil {
		return record, err
	}
	if err := checkDocumentOwner(tx.Context(), record); err != nil {
		return Record{}, err
	}
	return record, nil
}

func (s *Service) addTagsToResource(tx Transaction, in *api.AddTagsToResourceRequest) (*api.AddTagsToResourceResult, error) {
	tags, err := validateTags(in.Tags)
	if err != nil {
		return nil, err
	}
	record, err := s.tagDocument(tx, value(in.ResourceType), value(in.ResourceId), "AddTagsToResource", tagConditions(tags))
	if err != nil {
		return nil, err
	}
	if record.Tags == nil {
		record.Tags = make(map[string]string, len(tags))
	}
	maps.Copy(record.Tags, tags)
	if len(record.Tags) > 50 {
		return nil, failure("TooManyTagsError", "A document can have at most 50 tags.")
	}
	return &api.AddTagsToResourceResult{}, tx.PutDocument(record)
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
	record, err := s.tagDocument(tx, value(in.ResourceType), value(in.ResourceId), "RemoveTagsFromResource", map[string][]string{"aws:TagKeys": keys})
	if err != nil {
		return nil, err
	}
	for _, key := range keys {
		delete(record.Tags, key)
	}
	return &api.RemoveTagsFromResourceResult{}, tx.PutDocument(record)
}

func (s *Service) listTagsForResource(tx Transaction, in *api.ListTagsForResourceRequest) (*api.ListTagsForResourceResult, error) {
	record, err := s.tagDocument(tx, value(in.ResourceType), value(in.ResourceId), "ListTagsForResource", nil)
	if err != nil {
		return nil, err
	}
	out := &api.ListTagsForResourceResult{TagList: make(api.TagList, 0, len(record.Tags))}
	for _, key := range slices.Sorted(maps.Keys(record.Tags)) {
		out.TagList = append(out.TagList, api.Tag{Key: new(api.TagKey(key)), Value: new(api.TagValue(record.Tags[key]))})
	}
	return out, nil
}
