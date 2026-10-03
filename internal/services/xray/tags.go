package xray

import (
	"maps"
	"net/http"
	"slices"
	"strings"
	"unicode"

	api "stackd/internal/awsapi/xray"
)

func validateTags(tags api.TagList) (map[string]string, error) {
	if len(tags) > 50 {
		return nil, failure("InvalidRequestException", "A resource cannot have more than 50 tags.")
	}
	result := make(map[string]string, len(tags))
	for _, tag := range tags {
		key, text := value(tag.Key), value(tag.Value)
		if _, exists := result[key]; exists {
			return nil, failure("InternalFailure", "An internal error occurred.", http.StatusInternalServerError)
		}
		if strings.HasPrefix(strings.ToLower(key), "aws:") {
			return nil, failure("InvalidRequestException", "The aws: tag prefix is reserved.")
		}
		for _, text := range []string{key, text} {
			for _, r := range text {
				if !unicode.IsLetter(r) && !unicode.IsNumber(r) && !unicode.Is(unicode.Z, r) && !strings.ContainsRune("+-=._:/@", r) {
					return nil, failure("InvalidRequestException", "A tag contains an unsupported character.")
				}
			}
		}
		result[key] = text
	}
	return result, nil
}

func tagContext(resourceTags, requestTags map[string]string, keys []string) map[string][]string {
	conditions := make(map[string][]string, len(resourceTags)+len(requestTags)+1)
	for key, text := range resourceTags {
		conditions["aws:ResourceTag/"+key] = []string{text}
	}
	for key, text := range requestTags {
		conditions["aws:RequestTag/"+key] = []string{text}
	}
	if keys == nil {
		keys = slices.Sorted(maps.Keys(requestTags))
	} else {
		keys = slices.Clone(keys)
		slices.Sort(keys)
	}
	if len(keys) != 0 {
		conditions["aws:TagKeys"] = keys
	}
	return conditions
}

func tagList(tags map[string]string) api.TagList {
	result := make(api.TagList, 0, len(tags))
	for _, key := range slices.Sorted(maps.Keys(tags)) {
		result = append(result, api.Tag{Key: new(api.TagKey(key)), Value: new(api.TagValue(tags[key]))})
	}
	return result
}
