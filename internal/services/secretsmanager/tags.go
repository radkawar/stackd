package secretsmanager

import (
	"maps"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	api "stackd/internal/awsapi/secretsmanager"
)

func validateTags(tags api.TagListType) error {
	if len(tags) > 50 {
		return failure("InvalidParameterException", "A secret can have at most 50 tags.")
	}
	seen := make(map[string]struct{}, len(tags))
	for _, tag := range tags {
		key := value(tag.Key)
		if err := validateTagKey(key); err != nil {
			return err
		}
		if _, duplicate := seen[key]; duplicate {
			return failure("InvalidParameterException", "The same tag key cannot be specified more than once.")
		}
		seen[key] = struct{}{}
		if text := value(tag.Value); utf8.RuneCountInString(text) > 256 || !validTagText(text) {
			return failure("InvalidParameterException", "Tag values must contain at most 256 valid Unicode characters.")
		}
	}
	return nil
}

func validateTagKey(key string) error {
	if count := utf8.RuneCountInString(key); count < 1 || count > 128 || !validTagText(key) {
		return failure("InvalidParameterException", "Tag keys must contain between 1 and 128 valid Unicode characters.")
	}
	if strings.HasPrefix(strings.ToLower(key), "aws:") {
		return failure("InvalidParameterException", "Tag keys beginning with aws: are reserved for AWS.")
	}
	return nil
}

func validTagText(text string) bool {
	if !utf8.ValidString(text) {
		return false
	}
	for _, r := range text {
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) && !unicode.IsSpace(r) && !strings.ContainsRune("_./=+-@", r) {
			return false
		}
	}
	return true
}

func secretTags(tags map[string]string) api.TagListType {
	if tags == nil {
		return nil
	}
	out := make(api.TagListType, 0, len(tags))
	for _, key := range slices.Sorted(maps.Keys(tags)) {
		out = append(out, api.Tag{Key: str[api.TagKeyType](key), Value: str[api.TagValueType](tags[key])})
	}
	return out
}

func (s *Service) tagResource(tx Transaction, in *api.TagResourceInput) (*api.TagResourceOutput, error) {
	if in.Tags == nil {
		return nil, failure("InvalidParameterException", "The Tags parameter is required.")
	}
	if err := validateTags(in.Tags); err != nil {
		return nil, err
	}
	secret, err := resolveSecret(tx, value(in.SecretId))
	if err != nil {
		return nil, err
	}
	conditions := tagConditions(in.Tags)
	if err = s.authorize(tx, "TagResource", secret, conditions); err != nil {
		return nil, err
	}
	if err = checkWritable(tx.Context(), secret); err != nil {
		return nil, err
	}
	secret.Tags = maps.Clone(secret.Tags)
	if secret.Tags == nil {
		secret.Tags = make(map[string]string, len(in.Tags))
	}
	for _, tag := range in.Tags {
		secret.Tags[value(tag.Key)] = value(tag.Value)
	}
	count := 0
	for key := range secret.Tags {
		if !strings.HasPrefix(strings.ToLower(key), "aws:") {
			count++
		}
	}
	if count > 50 {
		return nil, failure("InvalidParameterException", "A secret can have at most 50 tags.")
	}
	if err = s.authorize(tx, "TagResource", secret, conditions); err != nil {
		if wireError(err).Code == "AccessDeniedException" {
			return nil, failure("AccessDeniedException", policyLockoutMessage)
		}
		return nil, err
	}
	secret.Changed = s.clock.Now()
	if err = tx.PutSecret(secret); err != nil {
		return nil, err
	}
	if err = s.refreshReplicas(tx, secret); err != nil {
		return nil, err
	}
	return &api.TagResourceOutput{}, nil
}

func (s *Service) untagResource(tx Transaction, in *api.UntagResourceInput) (*api.UntagResourceOutput, error) {
	if in.TagKeys == nil {
		return nil, failure("InvalidParameterException", "The TagKeys parameter is required.")
	}
	var keys []string
	if len(in.TagKeys) != 0 {
		keys = make([]string, len(in.TagKeys))
	}
	for i, key := range in.TagKeys {
		keys[i] = string(key)
		if err := validateTagKey(keys[i]); err != nil {
			return nil, err
		}
	}
	secret, err := resolveSecret(tx, value(in.SecretId))
	if err != nil {
		return nil, err
	}
	conditions := map[string][]string{"aws:TagKeys": keys}
	if err = s.authorize(tx, "UntagResource", secret, conditions); err != nil {
		return nil, err
	}
	if err = checkWritable(tx.Context(), secret); err != nil {
		return nil, err
	}
	secret.Tags = maps.Clone(secret.Tags)
	for _, key := range keys {
		delete(secret.Tags, key)
	}
	if err = s.authorize(tx, "UntagResource", secret, conditions); err != nil {
		if wireError(err).Code == "AccessDeniedException" {
			return nil, failure("AccessDeniedException", policyLockoutMessage)
		}
		return nil, err
	}
	// Native UntagResource preserves LastChangedDate and retains an empty
	// Tags collection after removing the last tag; never-tagged stays absent.
	if err = tx.PutSecret(secret); err != nil {
		return nil, err
	}
	if err = s.refreshReplicas(tx, secret); err != nil {
		return nil, err
	}
	return &api.UntagResourceOutput{}, nil
}
