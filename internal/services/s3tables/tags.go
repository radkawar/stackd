package s3tables

import (
	"context"
	"regexp"
	"slices"
	"strings"
	"unicode/utf8"

	api "stackd/internal/awsapi/s3tables"
	"stackd/internal/awswire"
)

// AWS S3 Tables supports tags on tables and table buckets, not namespaces or
// warehouse objects. Limits and character rules are shared by these resources:
// https://docs.aws.amazon.com/AmazonS3/latest/userguide/tagging.html
// https://docs.aws.amazon.com/AmazonS3/latest/userguide/table-tagging.html
var tagCharacters = regexp.MustCompile(`^[\p{L}\p{N}\p{Z}\s\x{000B}\x{0085}_.:/=+@-]*$`)

func validTagKey(key string) bool {
	n := utf8.RuneCountInString(key)
	return utf8.ValidString(key) && n >= 1 && n <= 128 && tagCharacters.MatchString(key) && !strings.HasPrefix(strings.ToLower(key), "aws:")
}

func validateTags(tags api.Tags) error {
	if len(tags) > 50 {
		return invalid("A resource can have at most 50 user-defined tags")
	}
	for key, value := range tags {
		if !validTagKey(string(key)) {
			return invalid("Invalid tag key; aws: is reserved")
		}
		if !utf8.ValidString(string(value)) || utf8.RuneCountInString(string(value)) > 256 || !tagCharacters.MatchString(string(value)) {
			return invalid("Invalid tag value")
		}
	}
	return nil
}

func domainTags(tags api.Tags) Tags {
	out := make(Tags, len(tags))
	for key, value := range tags {
		out[string(key)] = string(value)
	}
	return out
}

func requestTagContext(tags api.Tags, conditions map[string][]string) map[string][]string {
	if conditions == nil {
		conditions = map[string][]string{}
	}
	keys := make([]string, 0, len(tags))
	for key, value := range tags {
		conditions["aws:RequestTag/"+string(key)] = []string{string(value)}
		keys = append(keys, string(key))
	}
	slices.Sort(keys)
	if len(keys) != 0 {
		conditions["aws:TagKeys"] = keys
	}
	return conditions
}

// tagResourceARN resolves the exact immutable resource within the request scope.
// Deleted table rows are private cleanup state, never taggable public resources.
func tagResourceARN(ctx context.Context, r Reader, arn string) (string, map[string][]string, error) {
	sc := scopeFor(ctx)
	if !strings.HasPrefix(arn, bucketARN(sc, "")) {
		return "", nil, ErrNotFound
	}
	if strings.Contains(arn, "/table/") {
		row, err := r.TableByARN(sc, arn)
		if err != nil {
			return "", nil, err
		}
		if _, err = r.Bucket(sc, row.BucketARN); err != nil {
			return "", nil, err
		}
		return row.BucketARN, tableAuthorizationContext(row), nil
	}
	row, err := r.Bucket(sc, arn)
	if err != nil {
		return "", nil, err
	}
	return row.ARN, nil, nil
}

func (s *Service) TagResource(ctx context.Context, in *api.TagResourceInput) (*api.TagResourceOutput, *awswire.Error) {
	return command(s, ctx, "TagResource", in, func(ctx context.Context, tx Transaction, in *api.TagResourceInput) (*api.TagResourceOutput, error) {
		if in.Tags == nil {
			return nil, invalid("Tags are required")
		}
		if err := validateTags(in.Tags); err != nil {
			return nil, err
		}
		arn := value(in.ResourceArn)
		bucket, conditions, err := tagResourceARN(ctx, tx, arn)
		if err != nil {
			return nil, err
		}
		tags, err := s.authorizeTagged(ctx, tx, "TagResource", arn, bucket, requestTagContext(in.Tags, conditions))
		if err != nil {
			return nil, err
		}
		if tags == nil {
			tags = Tags{}
		}
		for key, value := range in.Tags {
			tags[string(key)] = string(value)
		}
		if len(tags) > 50 {
			return nil, invalid("A resource can have at most 50 user-defined tags")
		}
		return &api.TagResourceOutput{}, tx.PutResourceTags(scopeFor(ctx), arn, tags)
	})
}

func (s *Service) UntagResource(ctx context.Context, in *api.UntagResourceInput) (*api.UntagResourceOutput, *awswire.Error) {
	return command(s, ctx, "UntagResource", in, func(ctx context.Context, tx Transaction, in *api.UntagResourceInput) (*api.UntagResourceOutput, error) {
		if in.TagKeys == nil {
			return nil, invalid("TagKeys are required")
		}
		keys := make([]string, 0, len(in.TagKeys))
		for _, key := range in.TagKeys {
			if !validTagKey(string(key)) {
				return nil, invalid("Invalid tag key; aws: is reserved")
			}
			keys = append(keys, string(key))
		}
		slices.Sort(keys)
		keys = slices.Compact(keys)
		arn := value(in.ResourceArn)
		bucket, conditions, err := tagResourceARN(ctx, tx, arn)
		if err != nil {
			return nil, err
		}
		if conditions == nil {
			conditions = map[string][]string{}
		}
		if len(keys) != 0 {
			conditions["aws:TagKeys"] = keys
		}
		tags, err := s.authorizeTagged(ctx, tx, "UntagResource", arn, bucket, conditions)
		if err != nil {
			return nil, err
		}
		for _, key := range keys {
			delete(tags, key)
		}
		return &api.UntagResourceOutput{}, tx.PutResourceTags(scopeFor(ctx), arn, tags)
	})
}

func (s *Service) ListTagsForResource(ctx context.Context, in *api.ListTagsForResourceInput) (*api.ListTagsForResourceOutput, *awswire.Error) {
	return command(s, ctx, "ListTagsForResource", in, func(ctx context.Context, tx Transaction, in *api.ListTagsForResourceInput) (*api.ListTagsForResourceOutput, error) {
		arn := value(in.ResourceArn)
		bucket, conditions, err := tagResourceARN(ctx, tx, arn)
		if err != nil {
			return nil, err
		}
		tags, err := s.authorizeTagged(ctx, tx, "ListTagsForResource", arn, bucket, conditions)
		if err != nil {
			return nil, err
		}
		out := &api.ListTagsForResourceOutput{Tags: api.Tags{}}
		for key, value := range tags {
			out.Tags[api.TagKey(key)] = api.TagValue(value)
		}
		return out, nil
	})
}
