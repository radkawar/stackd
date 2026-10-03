package applicationautoscaling

import (
	"context"
	"slices"

	"stackd/internal/authorization"
	api "stackd/internal/awsapi/applicationautoscaling"
)

func targetConditions(key TargetKey, tags api.TagMap) map[string][]string {
	conditions := make(map[string][]string, len(tags)+2)
	if key.Namespace != "" {
		conditions["application-autoscaling:service-namespace"] = []string{key.Namespace}
	}
	if key.Dimension != "" {
		conditions["application-autoscaling:scalable-dimension"] = []string{key.Dimension}
	}
	for key, value := range tags {
		conditions["aws:ResourceTag/"+string(key)] = []string{string(value)}
	}
	return conditions
}

func requestTagConditions(conditions map[string][]string, tags api.TagMap) {
	keys := make([]string, 0, len(tags))
	for key, value := range tags {
		conditions["aws:RequestTag/"+string(key)] = []string{string(value)}
		keys = append(keys, string(key))
	}
	slices.Sort(keys)
	if len(keys) > 0 {
		conditions["aws:TagKeys"] = keys
	}
}

func (s *Service) authorize(ctx context.Context, action, resourceARN string, conditions map[string][]string) error {
	now := s.clock.Now()
	if err := s.authorizer.Authorize(ctx, authorization.Request{
		Action: "application-autoscaling:" + action, ResourceARN: resourceARN,
		ResourceAccountID: scopeFor(ctx).AccountID, Context: conditions, EvaluationTime: &now,
	}); err != nil {
		return err
	}
	return nil
}
