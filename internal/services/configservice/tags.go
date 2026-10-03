package configservice

import (
	"strings"
	"unicode/utf8"

	awsarn "github.com/aws/aws-sdk-go-v2/aws/arn"
	api "stackd/internal/awsapi/configservice"
)

func registerTags(s *Service) {
	register(s, "ListTagsForResource", s.listTagsForResource)
	register(s, "TagResource", s.tagResource)
	register(s, "UntagResource", s.untagResource)
}

func (s *Service) tagsForResource(tx Transaction, action, arn string) (map[string]string, error) {
	scope := scopeFor(tx.Context())
	tags, err := tx.Tags(scope, arn)
	if err != nil {
		return nil, err
	}
	if err := s.authorizeResourceTags(tx.Context(), action, arn, tags); err != nil {
		return nil, err
	}
	if err := tagResourceExists(tx, scope, arn); err != nil {
		return nil, err
	}
	return tags, nil
}

func tagResourceExists(r Reader, scope Scope, arn string) error {
	parsed, err := awsarn.Parse(arn)
	if err != nil || parsed.Service != "config" {
		return failure("ValidationException", "ResourceArn must be an AWS Config resource ARN.")
	}
	missing := failure("ResourceNotFoundException", "The resource does not exist.")
	if parsed.Partition != scope.Partition || parsed.AccountID != scope.AccountID || parsed.Region != scope.Region {
		return missing
	}
	kind, _, ok := strings.Cut(parsed.Resource, "/")
	if !ok {
		return missing
	}
	switch kind {
	case "configuration-recorder":
		row, found, err := r.Recorder(scope)
		if err != nil {
			return err
		}
		if found && row.ARN == arn {
			return nil
		}
	case "config-rule":
		rows, err := r.Rules(scope)
		if err != nil {
			return err
		}
		for _, row := range rows {
			if row.ARN == arn {
				return nil
			}
		}
	case "config-aggregator":
		rows, err := r.Aggregators(scope)
		if err != nil {
			return err
		}
		for _, row := range rows {
			if row.ARN == arn {
				return nil
			}
		}
	case "aggregation-authorization":
		rows, err := r.AggregationAuthorizations(scope)
		if err != nil {
			return err
		}
		for _, row := range rows {
			if row.ARN == arn {
				return nil
			}
		}
	}
	return missing
}

func mergeTags(current map[string]string, input []api.Tag) (map[string]string, error) {
	if current == nil {
		current = make(map[string]string, len(input))
	}
	seen := make(map[string]bool, len(input))
	for _, tag := range input {
		key := value(tag.Key)
		if err := validateTagKey(key); err != nil {
			return nil, err
		}
		if tag.Value == nil || utf8.RuneCountInString(value(tag.Value)) > 256 {
			return nil, failure("ValidationException", "Tag values are required and may contain at most 256 characters.")
		}
		if seen[key] {
			return nil, failure("ValidationException", "Duplicate tag keys are not allowed.")
		}
		seen[key] = true
		current[key] = value(tag.Value)
	}
	if len(current) > 50 {
		return nil, failure("TooManyTagsException", "A resource may have at most 50 tags.")
	}
	return current, nil
}

func validateTagKey(key string) error {
	if key == "" || utf8.RuneCountInString(key) > 128 || len(key) >= 4 && strings.EqualFold(key[:4], "aws:") {
		return failure("ValidationException", "Tag keys must contain 1 to 128 characters and cannot begin with aws:.")
	}
	return nil
}

func (s *Service) tagResource(tx Transaction, in *api.TagResourceInput) (*api.TagResourceOutput, error) {
	arn := value(in.ResourceArn)
	tags, err := s.tagsForResource(tx, "TagResource", arn)
	if err != nil {
		return nil, err
	}
	if len(in.Tags) == 0 {
		return nil, failure("ValidationException", "At least one tag is required.")
	}
	tags, err = mergeTags(tags, in.Tags)
	if err != nil {
		return nil, err
	}
	if err := tx.PutTags(scopeFor(tx.Context()), arn, tags); err != nil {
		return nil, err
	}
	return &api.TagResourceOutput{}, nil
}

func (s *Service) untagResource(tx Transaction, in *api.UntagResourceInput) (*api.UntagResourceOutput, error) {
	arn := value(in.ResourceArn)
	tags, err := s.tagsForResource(tx, "UntagResource", arn)
	if err != nil {
		return nil, err
	}
	if len(in.TagKeys) == 0 {
		return nil, failure("ValidationException", "At least one tag key is required.")
	}
	for _, key := range in.TagKeys {
		if err := validateTagKey(string(key)); err != nil {
			return nil, err
		}
		delete(tags, string(key))
	}
	if err := tx.PutTags(scopeFor(tx.Context()), arn, tags); err != nil {
		return nil, err
	}
	return &api.UntagResourceOutput{}, nil
}

func (s *Service) listTagsForResource(tx Transaction, in *api.ListTagsForResourceInput) (*api.ListTagsForResourceOutput, error) {
	arn := value(in.ResourceArn)
	tags, err := s.tagsForResource(tx, "ListTagsForResource", arn)
	if err != nil {
		return nil, err
	}
	// Native Config returns the complete tag set even with Limit=1 and ignores
	// NextToken. The generated model still enforces Limit's 0..100 input range.
	out := &api.ListTagsForResourceOutput{Tags: make(api.TagList, 0, len(tags))}
	for _, key := range sortedRuleKeys(tags) {
		out.Tags = append(out.Tags, api.Tag{Key: new(api.TagKey(key)), Value: new(api.TagValue(tags[key]))})
	}
	return out, nil
}
