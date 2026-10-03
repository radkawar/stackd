package s3

import (
	"net/url"
	"strings"
	"unicode"
	"unicode/utf8"

	api "stackd/internal/awsapi/s3"
	"stackd/internal/awswire"
)

func validateTags(in *api.Tagging, creatingBucket bool) ([]Tag, *awswire.Error) {
	if in == nil {
		return nil, failure("MalformedXML", "The XML you provided was not well-formed or did not validate against our published schema", 400)
	}
	seen := make(map[string]struct{}, len(in.TagSet))
	tags := make([]Tag, 0, len(in.TagSet))
	for _, tag := range in.TagSet {
		if tag.Key == nil || tag.Value == nil {
			return nil, failure("MalformedXML", "The XML you provided was not well-formed or did not validate against our published schema", 400)
		}
		key, val := value(tag.Key), value(tag.Value)
		if checkTagText(key, 1, 128) != tagTextValid {
			wire := failure("InvalidTag", "The TagKey you have provided is invalid", 400)
			wire.TagKey = key
			return nil, wire
		}
		if checkTagText(val, 0, 256) != tagTextValid {
			return nil, failure("InvalidTag", "The TagValue you have provided is invalid", 400)
		}
		if _, duplicate := seen[key]; duplicate {
			if creatingBucket {
				return nil, failure("InternalError", "We encountered an internal error. Please try again.", 500)
			}
			wire := failure("InvalidTag", "Cannot provide multiple Tags with the same key", 400)
			wire.TagKey = key
			return nil, wire
		}
		seen[key] = struct{}{}
		tags = append(tags, Tag{Key: key, Value: val})
	}
	return tags, nil
}

type tagTextIssue uint8

const (
	tagTextValid tagTextIssue = iota
	tagTextLength
	tagTextCharacters
)

func checkTagText(text string, min, max int) tagTextIssue {
	// Native S3 counts UTF-16 code units, including two for astral letters.
	length := 0
	for _, r := range text {
		length++
		if r > 0xffff {
			length++
		}
		if length > max {
			return tagTextLength
		}
		if unicode.IsLetter(r) || unicode.IsNumber(r) || unicode.Is(unicode.Z, r) {
			continue
		}
		switch r {
		case '+', '-', '=', '.', '_', ':', '/', '@':
		default:
			return tagTextCharacters
		}
	}
	if length < min {
		return tagTextLength
	}
	return tagTextValid
}

func outputTags(tags []Tag) api.TagSet {
	out := make(api.TagSet, 0, len(tags))
	for _, tag := range tags {
		out = append(out, api.Tag{Key: new(api.ObjectKey(tag.Key)), Value: new(api.Value(tag.Value))})
	}
	return out
}

func validateObjectTags(in *api.Tagging) ([]Tag, *awswire.Error) {
	if in != nil && len(in.TagSet) > 10 {
		return nil, failure("BadRequest", "Object tags cannot be greater than 10", 400)
	}
	tags, wire := validateTags(in, false)
	if wire != nil {
		return nil, wire
	}
	for _, tag := range tags {
		if strings.HasPrefix(tag.Key, "aws:") {
			return nil, failure("InvalidTag", "Your TagKey cannot be prefixed with aws:", 400)
		}
	}
	return tags, nil
}

func objectTagsHeader(header string) ([]Tag, *awswire.Error) {
	if header == "" {
		return nil, nil
	}
	const invalidHeader = "The header 'x-amz-tagging' shall be encoded as UTF-8 then URLEncoded URL query parameters without tag name duplicates."
	input := &api.Tagging{}
	seen := make(map[string]struct{})
	for part := range strings.SplitSeq(header, "&") {
		if part == "" {
			continue
		}
		rawKey, rawValue, _ := strings.Cut(part, "=")
		key, keyErr := url.QueryUnescape(rawKey)
		val, valueErr := url.QueryUnescape(rawValue)
		_, duplicate := seen[key]
		if keyErr != nil || valueErr != nil || key == "" || duplicate || !utf8.ValidString(key) || !utf8.ValidString(val) {
			return nil, failure("InvalidArgument", invalidHeader, 400)
		}
		seen[key] = struct{}{}
		input.TagSet = append(input.TagSet, api.Tag{Key: new(api.ObjectKey(key)), Value: new(api.Value(val))})
	}
	return validateObjectTags(input)
}
