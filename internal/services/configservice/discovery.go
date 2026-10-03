package configservice

import (
	"context"

	tagging "stackd/internal/services/resourcegroupstaggingapi"
)

// ListTaggingResources reads live Config identities and current tags in the
// caller's transaction, including never-tagged resources. The shared tagging
// owner owns previously-tagged membership, not a second copy of tag values.
func (s *Service) ListTaggingResources(ctx context.Context) ([]tagging.Resource, error) {
	var resources []tagging.Resource
	err := s.repository.View(ctx, func(r Reader) error {
		scope := scopeFor(r.Context())
		appendResource := func(arn, kind string) error {
			tags, err := r.Tags(scope, arn)
			if err != nil {
				return err
			}
			resources = append(resources, tagging.Resource{ARN: arn, ResourceType: "config:" + kind, Tags: tags})
			return nil
		}
		recorder, found, err := r.Recorder(scope)
		if err != nil {
			return err
		}
		if found {
			if err := appendResource(recorder.ARN, "configuration-recorder"); err != nil {
				return err
			}
		}
		rules, err := r.Rules(scope)
		if err != nil {
			return err
		}
		for _, rule := range rules {
			if err := appendResource(rule.ARN, "config-rule"); err != nil {
				return err
			}
		}
		aggregators, err := r.Aggregators(scope)
		if err != nil {
			return err
		}
		for _, aggregator := range aggregators {
			if err := appendResource(aggregator.ARN, "config-aggregator"); err != nil {
				return err
			}
		}
		authorizations, err := r.AggregationAuthorizations(scope)
		if err != nil {
			return err
		}
		for _, authorization := range authorizations {
			if err := appendResource(authorization.ARN, "aggregation-authorization"); err != nil {
				return err
			}
		}
		return nil
	})
	return resources, err
}
