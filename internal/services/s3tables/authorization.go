package s3tables

import "context"

// Both service-specific keys are String, not ArrayOfString. A namespace is its
// one typed name; never split it into synthetic hierarchy components or join an
// API NamespaceList to manufacture a different policy value.
// https://docs.aws.amazon.com/service-authorization/latest/reference/list_s3tables.html
func namespaceAuthorizationContext(namespace string) map[string][]string {
	if namespace == "" {
		return nil
	}
	return map[string][]string{"s3tables:namespace": {namespace}}
}

func tableAuthorizationContext(table Table) map[string][]string {
	return map[string][]string{
		"s3tables:tableName": {table.Name},
		"s3tables:namespace": {table.Namespace},
	}
}

func addTagContext(conditions map[string][]string, prefix string, tags Tags) {
	for key, value := range tags {
		conditions[prefix+key] = []string{value}
	}
}

// ResourceTag always describes the IAM target, while TableBucketTag describes
// its parent bucket. They must not be interchanged or inherited by the table.
// Read both through the current transaction, including publication rechecks.
func (s *Service) authorizeTagged(ctx context.Context, r Reader, action, arn, bucket string, conditions map[string][]string) (Tags, error) {
	if conditions == nil {
		conditions = map[string][]string{}
	}
	tags, err := r.ResourceTags(scopeFor(ctx), arn)
	if err != nil {
		return nil, err
	}
	addTagContext(conditions, "aws:ResourceTag/", tags)
	bucketTags := tags
	if arn != bucket {
		bucketTags, err = r.ResourceTags(scopeFor(ctx), bucket)
		if err != nil {
			return nil, err
		}
	}
	addTagContext(conditions, "s3tables:TableBucketTag/", bucketTags)
	if err = s.authorize(ctx, action, arn, conditions); err != nil {
		return nil, err
	}
	return tags, nil
}
